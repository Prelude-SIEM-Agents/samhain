/*
 * This is the header file for the trust function
 *
 * Author information:
 * Matt Bishop
 * Department of Computer Science
 * University of California at Davis
 * Davis, CA  95616-8562
 * phone (916) 752-8060
 * email bishop@cs.ucdavis.edu
 *
 * This code is placed in the public domain.  I do ask that
 * you keep my name associated with it, that you not represent
 * it as written by you, and that you preserve these comments.
 * This software is provided "as is" and without any guarantees
 * of any sort.
 */
/*
 * trustfile return codes
 */
#define	TF_ERROR	-1	/* can't check -- error */
#define	TF_NO		 0	/* file isn't trustworthy */
#define	TF_YES		 1	/* file is trustworthy */

/*
 * error codes
 */
#define TF_BADFILE	1	/* file name illegal */
#define TF_BADNAME	2	/* name not valid (prob. ran out of room) */
#define TF_BADSTAT	3	/* stat of file failed (see errno for why) */
#define TF_NOROOM	4	/* not enough allocated space */

/*
 * untrustworthy codes
 */
#define TF_BADUID	10	/* owner nmot trustworthy */
#define TF_BADGID	11	/* group writeable and member not trustworthy */
#define TF_BADOTH	12	/* anyone can write it */

/*
 * the basic constant -- what is the longest path name possible?
 * It should be at least the max path length as defined by system
 * + 4 ("/../") + max file name length as defined by system; this
 * should rarely fail (I rounded it up to 2048)
 */
#define MAXFILENAME	2048

/*
 * function declaration
 *
 * #ifdef __STDC__
 * extern int trustfile(char *, int *, int *);
 * #else
 * extern int trustfile();
 * #endif
 */
/*
 * these are useful global variables
 *
 * first set: who you gonna trust, by default?
 * 	if the user does not specify a trusted or untrusted set of users,
 *	all users are considered untrusted EXCEPT:
 *	UID 0 -- root	as root can do anything on most UNIX systems, this
 *			seems reasonable
 *	tf_euid -- programmer-selectable UID
 *			if the caller specifies a specific UID by putting
 *			it in this variable, it will be trusted; this is
 *			typically used to trust the effective UID of the
 *			process (note: NOT the real UID, which will cause all
 *			sorts of problems!)  By default, this is set to -1,
 *			so if it's not set, root is the only trusted user
 */
extern uid_t tf_euid;			/* space for EUID of process */

/*
 * second set: how do you report problems?
 *	tf_errno	on return when an error has occurred, this is set
 *			to the code indicating the reason for the error:
 *			   TF_BADFILE	passed NULL for pointer to file name
 *			   TF_BADNAME	could not expand to full path name
 *			   TF_BADSTAT	stat failed; usu. file doesn't exist
 *			   TF_BADUID	owner untrusted
 *			   TF_BADGID	group untrusted & can write
 *			   TF_BADOTH	anyone can write
 *			the value is preserved across calls where no error
 *			occurs, just like errno(2)
 *	tf_path		if error occurs and a file name is involved, this
 *			contains the file name causing the problem
 */
extern char tf_path[MAXFILENAME];	/* error path for trust function */

extern uid_t rootonly[];
extern int  EUIDSLOT;

