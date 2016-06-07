#include "config_xor.h"

#ifdef USE_LOGFILE_MONITOR

#include <string.h>
#include <ctype.h>

#undef  FIL__
#define FIL__  _("sh_log_repeat.c")

#include "samhain.h"
#include "sh_pthread.h"
#include "sh_utils.h"
#include "sh_string.h"
#include "sh_log_check.h"
#include "sh_log_evalrule.h"

#define SH_NHIST   12
#define SH_NFINT    5
#define SH_NFIELDS  5*sizeof(SINT32) /* 16 */
#define SH_NBLOCK  63

typedef enum
{
  SH_GFLAG_EMAIL = 1 << 0,
  SH_GFLAG_PATH  = 1 << 1,
  SH_GFLAG_IP    = 1 << 2,
  SH_GFLAG_FQDN  = 1 << 3,
  SH_GFLAG_NUM   = 1 << 4,
  SH_GFLAG_ELSE  = 1 << 5,

  SH_GFLAG_XNUM  = 1 << 6,
  SH_GFLAG_CHAR  = 1 << 7,
  SH_GFLAG_USC   = 1 << 8
} SH_GFlags;


/* 64 bytes 
 */
struct gestalt {
  unsigned char hist[SH_NHIST];      /* time histogram 12 minutes   */
  union {
    unsigned char flags[SH_NFIELDS]; /* flags indicating field type */
    SINT32        flint[SH_NFINT];
  } f;
  UINT16      sum[SH_NFIELDS];     /* checksum of field           */
  UINT16      ltime;               /* last time, in minutes       */
  UINT16      total;               /* seen how often?             */
};

static unsigned int     nrec = 0;    /* size of array               */
static unsigned int     urec = 0;    /* in use thereof              */
static struct gestalt * arec = NULL; /* array                       */

static int      repeat_count = 24;   /* triggers report             */
static int     clean_counter = 0;    /* cleanup after N inserts     */
static int        free_slots = 0;    /* free slots available        */

#define SH_CLEANUP 256

static struct gestalt * add_entry (unsigned char * flags, UINT16 * sum, 
				   time_t ltime)
{
  struct gestalt * array = NULL;

 start:
  if (urec < nrec)
    {
      if (free_slots)
	{
	  unsigned int i;
	  for (i = 0; i < urec; ++i)
	    {
	      if (arec[i].total == 0)
		{
		  array = &arec[i];
		  --free_slots;
		  break;
		}
	    }
	}

      if (!array)
	{
	  array = &arec[urec];
	  ++urec;
	}

      memcpy(array->sum,       sum, sizeof(UINT16)      * SH_NFIELDS);
      memcpy(array->f.flags, flags, sizeof(unsigned char) * SH_NFIELDS);
      memset(array->hist,        0, sizeof(unsigned char) * SH_NHIST);

      array->ltime               = (UINT16)(ltime % 60);
      array->hist[SH_NHIST-1]    = 1;
      array->total               = 1;

      ++clean_counter;
      return array;
    }

  array =    SH_ALLOC(sizeof(struct gestalt) * (nrec + SH_NBLOCK + 1));
  memset(array,    0, sizeof(struct gestalt) * (nrec + SH_NBLOCK + 1));
  memcpy(array, arec, sizeof(struct gestalt) * (nrec));

  nrec += (SH_NBLOCK + 1);
  goto start;
}

static UINT16 shift_history(unsigned char * hist, unsigned int shift, 
			      UINT16 total)
{
  unsigned int i, j = 0;

  if (shift >= SH_NHIST)
    {
      memset(hist,      0, sizeof(unsigned char) * SH_NHIST);
      return 0;
    }

  for (i = shift; i < SH_NHIST; ++i)
    {
      if (j < shift)
	total  -= hist[j];
      hist[j] = hist[i];
      ++j;
    }
  for (i = (SH_NHIST-shift); i < SH_NHIST; ++i)
    {
      hist[i] = 0;
    }
  return total;
}
 
static void update_entry (struct gestalt * array, time_t ltime)
{
  UINT16 ntime = (UINT16)(ltime % 60);

  if (array->ltime == ntime)
    {
      if (array->hist[SH_NHIST-1] < 255) 
	{
	  ++(array->hist[SH_NHIST-1]);
	  ++(array->total);
	}
    }
  else if (array->ltime < ntime)
    {
      unsigned int shift = ntime - array->ltime;
      array->total = shift_history(array->hist, shift, array->total);
      array->hist[SH_NHIST-1] = 1;
      array->ltime = ntime;
      ++(array->total);
    }
}

static struct gestalt * update_or_add (unsigned char * flags, UINT16 * sum, 
				       time_t ltime)
{
  SINT32 flint[SH_NFINT];
 start:

  if (arec)
    {
      unsigned int i;
      struct gestalt * array = arec;

      memcpy(flint, flags, SH_NFIELDS);

      for (i = 0; i < urec; ++i)
	{
	  /* Check whether field types match. Integer
	   * comparison is much faster than memcmp() [tested].
	   */
	  if (flint[0] == array->f.flint[0] &&
	      flint[1] == array->f.flint[1] &&
	      flint[2] == array->f.flint[2] &&
	      flint[3] == array->f.flint[3] &&
	      flint[4] == array->f.flint[4])
	    {
	      unsigned int j; 
	      int c1 = 0, c2 = 0;
	      UINT16 * asum = array->sum;

	      for (j = 0; j < SH_NFIELDS; ++j)
		{
		  if (flags[j] == SH_GFLAG_ELSE)
		    {
		      ++c1;
		      if (asum[j] == sum[j]) 
			++c2;
		    }
		}

	      if (c1 == c2)
		{
		  /* Found a matching entry, update time histogram
		   */
		  update_entry (array, ltime);
		  return array;
		}
	    }
	  ++array;
	}

      /* No match found, create a new entry
       */
      array = add_entry (flags, sum, ltime);
      return array;
    }
  
  arec = SH_ALLOC(sizeof(struct gestalt) * SH_NBLOCK);
  nrec = SH_NBLOCK;
  urec = 0;

  goto start;
}

/* --------------------------------------------------------------------
 *
 * crc16 checksum from the linux kernel.
 * This source code is licensed under the GNU General Public License,
 * Version 2. 
 */

/** CRC table for the CRC-16. The poly is 0x8005 (x^16 + x^15 + x^2 + 1) */
UINT16 const crc16_table[256] = {
  0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
  0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
  0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
  0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
  0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
  0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
  0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
  0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
  0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
  0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
  0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
  0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
  0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
  0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
  0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
  0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
  0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
  0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
  0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
  0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
  0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
  0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
  0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
  0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
  0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
  0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
  0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
  0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
  0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
  0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
  0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
  0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};

static inline UINT16 crc16_byte(UINT16 crc, const unsigned char data)
{
  return (crc >> 8) ^ crc16_table[(crc ^ data) & 0xff];
}

/**
 * crc16 - compute the CRC-16 for the data buffer
 * @crc:        previous CRC value
 * @buffer:     data pointer
 * @len:        number of bytes in the buffer
 *
 * Returns the updated CRC value.
 */
static inline UINT16 crc16(UINT16 crc, const unsigned char * buffer, 
			     size_t len)
{
  while (len--)
    crc = crc16_byte(crc, *buffer++);
  return crc;
}


/* end crc16 code
 *
 * -------------------------------------------------------------------- */

static void  classify(char ** splits, size_t * lengths, unsigned int nfields, 
		      unsigned char * flags, UINT16 * sums)
{
  unsigned int i;
  unsigned int flag;

  /* flags we don't want to see in XYZ 
   */
  static int m_ip    = SH_GFLAG_PATH|SH_GFLAG_EMAIL|SH_GFLAG_USC|SH_GFLAG_ELSE|SH_GFLAG_CHAR|SH_GFLAG_XNUM;
  static int m_num   = SH_GFLAG_PATH|SH_GFLAG_EMAIL|SH_GFLAG_USC|SH_GFLAG_ELSE|SH_GFLAG_CHAR;
  static int m_fqdn  = SH_GFLAG_PATH|SH_GFLAG_EMAIL|SH_GFLAG_USC|SH_GFLAG_ELSE;
  static int m_email = SH_GFLAG_PATH;

  nfields = (nfields > SH_NFIELDS) ? SH_NFIELDS : nfields;

  for (i = 0; i < nfields; ++i) 
    {
      char *p = splits[i];
      unsigned int np   = 0;
      unsigned int fqdn = 0;

      flag = 0;

      while (*p)
	{
	  if (isxdigit((unsigned int)*p))
	    {
	      if (isdigit((unsigned int)*p))
		{
		  flag |= SH_GFLAG_NUM;
		}
	      else
		{
		  flag |= SH_GFLAG_XNUM;
		}
	    }
	  else if (*p == '.')
	    {
	      flag |= SH_GFLAG_IP;
	      ++np;
	    }
	  else if (*p == '/')
	    {
	      flag |= SH_GFLAG_PATH;
	    }
	  else if (*p == '@')
	    {
	      flag |= SH_GFLAG_EMAIL;
	    }
	  else if (*p == '-')
	    {
	      flag |= SH_GFLAG_FQDN;
	    }
	  else if (*p == '_')
	    {
	      flag |= SH_GFLAG_USC;
	    }
	  else if (isalpha((unsigned int)*p))
	    {
	      if (flag & SH_GFLAG_IP)
		++fqdn;
	      flag |= SH_GFLAG_CHAR;
	    }
	  else if (!isascii((unsigned int)*p))
	    {
	      flags[i] = SH_GFLAG_ELSE;
	      break;
	    }
	  else
	    {
	      flag |= SH_GFLAG_ELSE;
	    }
	  ++p;
	}

      if (flags[i] == 0)
	{
	  if (0 == (flag & m_ip)         && 
	      0 != (flag & SH_GFLAG_IP)  && 
	      0 != (flag & SH_GFLAG_NUM) && 
	      np > 2)
	    {
	      flags[i] = SH_GFLAG_IP;
	    }
	  else if (0 == (flag & m_num) && 
		   (0 != (flag & SH_GFLAG_NUM) || 0 != (flag & SH_GFLAG_XNUM)))
	    {
	      flags[i] = SH_GFLAG_NUM;
	    }
	  else if (0 == (flag & m_fqdn)        && 
		   0 != (flag & SH_GFLAG_IP)   && 
		   0 != (flag & SH_GFLAG_CHAR) && 
		   fqdn)
	    {
	      flags[i] = SH_GFLAG_FQDN;
	    }
	  else if ('/' == splits[i][0])
	    {
	      flags[i] = SH_GFLAG_PATH;
	    }
	  else if (0 == (flag & m_email)        && 
		   0 != (flag & SH_GFLAG_EMAIL) && 
		   0 != (flag & SH_GFLAG_CHAR)) 
	    {
	      flags[i] = SH_GFLAG_EMAIL;
	    }
	  else 
	    {
	      flags[i] = SH_GFLAG_ELSE;
	    }
	}

      /* CRC-16 checksum
       */ 
      sums[i] = crc16(0, (unsigned char *) splits[i], lengths[i]);
    }

  return;
}

static void cleanup_array (time_t ltime)
{
  UINT16 ntime = (UINT16)(ltime % 60);

  if (ntime > 12) ntime -= 12;

  if (arec && urec > 0)
    {
      struct gestalt * array;
      unsigned int i, last, urec_orig = urec;

      last = urec-1;
      array = &arec[0];
  
      for (i = 0; i < urec_orig; ++i)
	{
	  if (array->ltime < ntime)
	    {
	      memset(array,    0, sizeof(struct gestalt));
	      if (i != last)
		++free_slots;
	      else
		--urec;
	    }
	}
      ++array;
    }
  clean_counter = 0;
  return;
}

/* ----------------------------------------------------------------------
 *
 *   Public functions
 */

int sh_repeat_set_trigger (const char * str)
{
  unsigned long  value;
  char * foo;

  value = (size_t) strtoul(str, &foo, 0);

  if (*foo == '\0' && value < 65535) {
    repeat_count = value;
    return 0;
  }
  return -1;
}

static char * sh_repeat_queue = NULL;

int sh_repeat_set_queue (const char * str)
{
  if (!str)
    return -1;
  if (sh_repeat_queue)
    SH_FREE(sh_repeat_queue);
  sh_repeat_queue = sh_util_strdup(str);
  return 0;
}

static int sh_repeat_cron = S_FALSE;

int sh_repeat_set_cron (const char * str)
{
  return sh_util_flagval(str, &sh_repeat_cron);
}

int sh_repeat_message_check (const sh_string * host, 
			     const sh_string * msg, 
			     time_t ltime)
{
  struct gestalt * array;

  UINT16         sums[SH_NFIELDS] = { 0 };
  unsigned char flags[SH_NFIELDS] = { 0 };

  /* split message into SH_NFIELDS+1, discard last  */

  unsigned int nfields = SH_NFIELDS+1;
  size_t       lengths[SH_NFIELDS+1];
  char *       new;
  char **      splits;

  if (repeat_count == 0)
    return 0;

  if (sh_repeat_cron == S_FALSE)
    {
      char * s = sh_string_str(msg);

      if (0 == strcmp(s, _("cron")) || 0 == strcmp(s, _("CRON")))
	return 0;
    }

  new = sh_util_strdup_l(sh_string_str(msg), sh_string_len(msg));

  splits = split_array_token (new, &nfields, lengths, 
			      " :,()='[]<>\t\n");

  /* classify fields                                */

  classify (splits, lengths, nfields, flags, sums); 

  /* compare                                        */

  array = update_or_add (flags, sums, ltime);

  /* report                                         */

  if (array->total > repeat_count)
    {
      volatile int repeat = array->total;
      char * tmpmsg;
      char * tmphost;
      sh_string * alias;

      /* issue report             */

      SH_MUTEX_LOCK(mutex_thread_nolog);
      tmphost = sh_util_safe_name (sh_string_str(host));
      tmpmsg  = sh_util_safe_name_keepspace (sh_string_str(msg));
      sh_error_handle (sh_log_lookup_severity(sh_repeat_queue), 
		       FIL__, __LINE__, 0, MSG_LOGMON_BURST, 
		       repeat, tmpmsg, tmphost);
      alias = sh_log_lookup_alias(sh_repeat_queue);
      if (alias)
	{
	  sh_error_mail (sh_string_str(alias), 
			 sh_log_lookup_severity(sh_repeat_queue), 
			 FIL__, __LINE__, 0, MSG_LOGMON_BURST, 
			 repeat, tmpmsg, tmphost);
	}
      SH_FREE(tmpmsg);
      SH_FREE(tmphost);
      SH_MUTEX_UNLOCK(mutex_thread_nolog);

      /* mark slot as free        */

      memset(array,    0, sizeof(struct gestalt));
      if (array != &arec[urec-1])
	++free_slots;
      else
	urec -= 1;
    }

  SH_FREE(new);

  /* run cleanup routine                            */

  if (clean_counter >= SH_CLEANUP)
    {
      cleanup_array(ltime);
    }

  return 0;
}

#endif
