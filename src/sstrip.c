/* sstrip, version 2.0: Copyright (C) 1999-2001 by Brian Raiter, under the
 * GNU General Public License. No warranty. See LICENSE for details.
 */

/* Modified for portability and 64bit/32bit elf executables, Rainer Wichmann */
 
#include "config.h" 

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<unistd.h>
#include	<fcntl.h>

#if !defined(__ia64)  && !defined(__ia64__)  && !defined(__itanium__) &&  \
    !defined(__alpha) && !defined(__alpha__) && \
    (defined(HAVE_ELF_H) || defined(HAVE_LINUX_ELF_H)) && \
    (defined(__linux__)  || defined(__FreeBSD__)) && \
    (defined(__i386__)   || defined(__i386) || defined(i386))

/* || defined(__sun) || defined(__sun__) || defined(sun) */


#if defined(HAVE_ELF_H)
#include        <elf.h>
#else
#include        <linux/elf.h>
#endif

#ifndef TRUE
#define	TRUE		1
#define	FALSE		0
#endif

#ifndef ELFCLASS32
#define ELFCLASS32      1               /* 32-bit objects */
#endif
#ifndef ELFCLASS64
#define ELFCLASS64      2               /* 64-bit objects */
#endif



/* The name of the program.
 */
static char const      *progname;

/* The name of the current file.
 */
static char const      *filename;


/* A simple error-handling function. FALSE is always returned for the
 * convenience of the caller.
 */
static int err(char const *errmsg)
{
    fprintf(stderr, "%s: %s: %s\n", progname, filename, errmsg);
    return FALSE;
}

/* A macro for I/O errors: The given error message is used only when
 * errno is not set.
 */
#define	ferr(msg)	(err(errno ? strerror(errno) : (msg)))

/* readelfheader() reads the ELF header into our global variable, and
 * checks to make sure that this is in fact a file that we should be
 * munging.
 */
static int readelfheader_32(int fd, Elf32_Ehdr *ehdr)
{
    errno = 0;
    if (read(fd, ehdr, sizeof *ehdr) != sizeof *ehdr)
	return ferr("missing or incomplete ELF header.");

    /* Check the ELF signature.
     */
    if (!(ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
	  ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
	  ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
	  ehdr->e_ident[EI_MAG3] == ELFMAG3))
	return err("missing ELF signature.");

    /* Compare the file's class and endianness with the program's.
     */
#ifdef ELF_DATA
    if (ehdr->e_ident[EI_DATA] != ELF_DATA)
	return err("ELF file has different endianness.");
#endif

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS32)
	return FALSE;

    /* Check the target architecture.
     */
#ifdef ELF_ARCH
    if (ehdr->e_machine != ELF_ARCH)
	return err("ELF file created for different architecture.");
#endif

    /* Verify the sizes of the ELF header and the program segment
     * header table entries.
     */
    if (ehdr->e_ehsize != sizeof(Elf32_Ehdr))
	return err("unrecognized ELF header size.");
    if (ehdr->e_phentsize != sizeof(Elf32_Phdr))
	return err("unrecognized program segment header size.");

    /* Finally, check the file type.
     */
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
	return err("not an executable or shared-object library.");

    return TRUE;
}

static int readelfheader_64(int fd, Elf64_Ehdr *ehdr)
{
    errno = 0;

    if (lseek(fd, 0, SEEK_SET))
	return ferr("could not rewind file");

    if (read(fd, ehdr, sizeof *ehdr) != sizeof *ehdr)
	return ferr("missing or incomplete ELF header.");

    /* Check the ELF signature.
     */
    if (!(ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
	  ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
	  ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
	  ehdr->e_ident[EI_MAG3] == ELFMAG3))
	return err("missing ELF signature.");

    /* Compare the file's class and endianness with the program's.
     */
#ifdef ELF_DATA
    if (ehdr->e_ident[EI_DATA] != ELF_DATA)
	return err("ELF file has different endianness.");
#endif

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
	return err("ELF file has different word size.");

    /* Check the target architecture.
     */
#ifdef ELF_ARCH
    if (ehdr->e_machine != ELF_ARCH)
	return err("ELF file created for different architecture.");
#endif

    /* Verify the sizes of the ELF header and the program segment
     * header table entries.
     */
    if (ehdr->e_ehsize != sizeof(Elf64_Ehdr))
	return err("unrecognized ELF header size.");
    if (ehdr->e_phentsize != sizeof(Elf64_Phdr))
	return err("unrecognized program segment header size.");

    /* Finally, check the file type.
     */
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
	return err("not an executable or shared-object library.");

    return TRUE;
}

/* readphdrtable() loads the program segment header table into memory.
 */
static int readphdrtable_32(int fd, Elf32_Ehdr const *ehdr, Elf32_Phdr **phdrs)
{
    size_t	size;

    if (!ehdr->e_phoff || !ehdr->e_phnum)
	return err("ELF file has no program header table.");

    size = ehdr->e_phnum * sizeof **phdrs;
    if (!(*phdrs = calloc(1,size)))
	return err("Out of memory!");

    errno = 0;
    if (read(fd, *phdrs, size) != (ssize_t)size)
	return ferr("missing or incomplete program segment header table.");

    return TRUE;
}

static int readphdrtable_64(int fd, Elf64_Ehdr const *ehdr, Elf64_Phdr **phdrs)
{
    size_t	size;

    if (!ehdr->e_phoff || !ehdr->e_phnum)
	return err("ELF file has no program header table.");

    size = ehdr->e_phnum * sizeof **phdrs;
    if (!(*phdrs = calloc(1,size)))
	return err("Out of memory!");

    errno = 0;
    if (read(fd, *phdrs, size) != (ssize_t)size)
	return ferr("missing or incomplete program segment header table.");

    return TRUE;
}

/* getmemorysize() determines the offset of the last byte of the file
 * that is referenced by an entry in the program segment header table.
 * (Anything in the file after that point is not used when the program
 * is executing, and thus can be safely discarded.)
 */
static int getmemorysize_32(Elf32_Ehdr const *ehdr, Elf32_Phdr const *phdrs,
			    unsigned long *newsize)
{
    Elf32_Phdr   const   *phdr;
    unsigned long	size, n;
    unsigned int	i;

    /* Start by setting the size to include the ELF header and the
     * complete program segment header table.
     */
    size = ehdr->e_phoff + ehdr->e_phnum * sizeof *phdrs;
    if (size < sizeof *ehdr)
	size = sizeof *ehdr;

    /* Then keep extending the size to include whatever data the
     * program segment header table references.
     */
    for (i = 0, phdr = phdrs ; i < ehdr->e_phnum ; ++i, ++phdr) {
	if (phdr->p_type != PT_NULL) {
	    n = phdr->p_offset + phdr->p_filesz;
	    if (n > size)
		size = n;
	}
    }

    *newsize = size;
    return TRUE;
}

static int getmemorysize_64(Elf64_Ehdr const *ehdr, Elf64_Phdr const *phdrs,
			    unsigned long *newsize)
{
    Elf64_Phdr   const   *phdr;
    unsigned long  	  size, n;
    unsigned int	  i;

    /* Start by setting the size to include the ELF header and the
     * complete program segment header table.
     */
    size = ehdr->e_phoff + ehdr->e_phnum * sizeof *phdrs;
    if (size < sizeof *ehdr)
	size = sizeof *ehdr;

    /* Then keep extending the size to include whatever data the
     * program segment header table references.
     */
    for (i = 0, phdr = phdrs ; i < ehdr->e_phnum ; ++i, ++phdr) {
	if (phdr->p_type != PT_NULL) {
	    n = phdr->p_offset + phdr->p_filesz;
	    if (n > size)
		size = n;
	}
    }

    *newsize = size;
    return TRUE;
}

/* truncatezeros() examines the bytes at the end of the file's
 * size-to-be, and reduces the size to exclude any trailing zero
 * bytes.
 */
static int truncatezeros(int fd, unsigned long *newsize)
{
    unsigned char	contents[1024];
    unsigned long	size, n;

    size = *newsize;
    do {
	n = sizeof contents;
	if (n > size)
	    n = size;
	if (lseek(fd, size - n, SEEK_SET) == (off_t)-1)
	    return ferr("cannot seek in file.");
	if (read(fd, contents, n) != (ssize_t)n)
	    return ferr("cannot read file contents");
	while (n && !contents[--n])
	    --size;
    } while (size && !n);

    /* Sanity check.
     */
    if (!size)
	return err("ELF file is completely blank!");

    *newsize = size;
    return TRUE;
}

/* modifyheaders() removes references to the section header table if
 * it was stripped, and reduces program header table entries that
 * included truncated bytes at the end of the file.
 */
static int modifyheaders_32(Elf32_Ehdr *ehdr, Elf32_Phdr *phdrs,
			    unsigned long newsize)
{
    Elf32_Phdr   *phdr;
    unsigned int  i;

    /* If the section header table is gone, then remove all references
     * to it in the ELF header.
     */
    if (ehdr->e_shoff >= newsize) {
	ehdr->e_shoff = 0;
	ehdr->e_shnum = 0;
	ehdr->e_shentsize = 0;
	ehdr->e_shstrndx = 0;
    }

    /* The program adjusts the file size of any segment that was
     * truncated. The case of a segment being completely stripped out
     * is handled separately.
     */
    for (i = 0, phdr = phdrs ; i < ehdr->e_phnum ; ++i, ++phdr) {
	if (phdr->p_offset >= newsize) {
	    phdr->p_offset = newsize;
	    phdr->p_filesz = 0;
	} else if (phdr->p_offset + phdr->p_filesz > newsize) {
	    phdr->p_filesz = newsize - phdr->p_offset;
	}
    }

    return TRUE;
}

static int modifyheaders_64(Elf64_Ehdr *ehdr, Elf64_Phdr *phdrs,
			    unsigned long newsize)
{
    Elf64_Phdr   *phdr;
    unsigned int  i;

    /* If the section header table is gone, then remove all references
     * to it in the ELF header.
     */
    if (ehdr->e_shoff >= newsize) {
	ehdr->e_shoff = 0;
	ehdr->e_shnum = 0;
	ehdr->e_shentsize = 0;
	ehdr->e_shstrndx = 0;
    }

    /* The program adjusts the file size of any segment that was
     * truncated. The case of a segment being completely stripped out
     * is handled separately.
     */
    for (i = 0, phdr = phdrs ; i < ehdr->e_phnum ; ++i, ++phdr) {
	if (phdr->p_offset >= newsize) {
	    phdr->p_offset = newsize;
	    phdr->p_filesz = 0;
	} else if (phdr->p_offset + phdr->p_filesz > newsize) {
	    phdr->p_filesz = newsize - phdr->p_offset;
	}
    }

    return TRUE;
}

/* commitchanges() writes the new headers back to the original file
 * and sets the file to its new size.
 */
static int commitchanges_32(int fd, Elf32_Ehdr const *ehdr, Elf32_Phdr *phdrs,
			    unsigned long newsize)
{
    size_t	n;

    /* Save the changes to the ELF header, if any.
     */
    if (lseek(fd, 0, SEEK_SET))
	return ferr("could not rewind file");
    errno = 0;
    if (write(fd, ehdr, sizeof *ehdr) != sizeof *ehdr)
	return err("could not modify file");

    /* Save the changes to the program segment header table, if any.
     */
    if (lseek(fd, ehdr->e_phoff, SEEK_SET) == (off_t)-1) {
	err("could not seek in file.");
	goto warning;
    }
    n = ehdr->e_phnum * sizeof *phdrs;
    if (write(fd, phdrs, n) != (ssize_t)n) {
	err("could not write to file");
	goto warning;
    }

    /* Eleventh-hour sanity check: don't truncate before the end of
     * the program segment header table.
     */
    if (newsize < ehdr->e_phoff + n)
	newsize = ehdr->e_phoff + n;

    /* Chop off the end of the file.
     */
    if (ftruncate(fd, newsize)) {
	err("could not resize file");
	goto warning;
    }

    return TRUE;

  warning:
    return err("ELF file may have been corrupted!");
}

static int commitchanges_64(int fd, Elf64_Ehdr const *ehdr, Elf64_Phdr *phdrs,
			    unsigned long newsize)
{
    size_t	n;

    /* Save the changes to the ELF header, if any.
     */
    if (lseek(fd, 0, SEEK_SET))
	return ferr("could not rewind file");
    errno = 0;
    if (write(fd, ehdr, sizeof *ehdr) != sizeof *ehdr)
	return err("could not modify file");

    /* Save the changes to the program segment header table, if any.
     */
    if (lseek(fd, ehdr->e_phoff, SEEK_SET) == (off_t)-1) {
	err("could not seek in file.");
	goto warning;
    }
    n = ehdr->e_phnum * sizeof *phdrs;
    if (write(fd, phdrs, n) != (ssize_t)n) {
	err("could not write to file");
	goto warning;
    }

    /* Eleventh-hour sanity check: don't truncate before the end of
     * the program segment header table.
     */
    if (newsize < ehdr->e_phoff + n)
	newsize = ehdr->e_phoff + n;

    /* Chop off the end of the file.
     */
    if (ftruncate(fd, newsize)) {
	err("could not resize file");
	goto warning;
    }

    return TRUE;

  warning:
    return err("ELF file may have been corrupted!");
}

/* main() loops over the cmdline arguments, leaving all the real work
 * to the other functions.
 */
int main(int argc, char *argv[])
{
    int			fd;
    int                 is_32bit_elf;
    Elf32_Ehdr		ehdr32;
    Elf32_Phdr	       *phdrs32 = NULL;
    Elf64_Ehdr		ehdr64;
    Elf64_Phdr	       *phdrs64 = NULL;
    unsigned long	newsize;
    char	      **arg;
    int			failures = 0;

    if (argc < 2 || argv[1][0] == '-') {
	printf("Usage: sstrip FILE...\n"
	       "sstrip discards all nonessential bytes from an executable.\n\n"
	       "Version 2.0 Copyright (C) 2000,2001 Brian Raiter.\n"
	       "This program is free software, licensed under the GNU\n"
	       "General Public License. There is absolutely no warranty.\n");
	return EXIT_SUCCESS;
    }

    progname = argv[0];

    for (arg = argv + 1 ; *arg != NULL ; ++arg) {
	filename = *arg;

	fd = open(*arg, O_RDWR);
	if (fd < 0) {
	    ferr("can't open");
	    ++failures;
	    continue;
	}

	if (readelfheader_32(fd, &ehdr32)) {
	  is_32bit_elf = TRUE;
	} 
	else if (readelfheader_64(fd, &ehdr64)) {
	  is_32bit_elf = FALSE;
	}
	else {
	  close(fd);
	  return EXIT_FAILURE;
	}

	if (is_32bit_elf) {
	  if (!(readphdrtable_32(fd, &ehdr32, &phdrs32)	        &&
	      getmemorysize_32(&ehdr32, phdrs32, &newsize)	&&
	      truncatezeros(fd, &newsize)		        &&
	      modifyheaders_32(&ehdr32, phdrs32, newsize)	&&
	      commitchanges_32(fd, &ehdr32, phdrs32, newsize)))
	    ++failures;
	} 
	else {
	  if (!(readphdrtable_64(fd, &ehdr64, &phdrs64)	        &&
	      getmemorysize_64(&ehdr64, phdrs64, &newsize)	&&
	      truncatezeros(fd, &newsize)		        &&
	      modifyheaders_64(&ehdr64, phdrs64, newsize)	&&
	      commitchanges_64(fd, &ehdr64, phdrs64, newsize)))
	    ++failures;
	}

	close(fd);
    }

    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}

#else

int main()
{
  return (EXIT_SUCCESS);
}

#endif
