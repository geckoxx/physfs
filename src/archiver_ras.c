/*
 * RAS support routines for PhysicsFS.
 *
 *  This archiver handles the archive format utilized by Max Payne 2.
 *
 *  ========================================================================
 *
 *  RAS Format
 *
 *  Header
 *   (4 bytes)  signature = 'RAS '
 *   (4 bytes)  seed
 *
 *  Encrypted Header
 *   (4 bytes)  file count
 *   (4 bytes)  directory count
 *   (4 bytes)  files-info length
 *   (4 bytes)  directories-info length
 *   (4 bytes)  unknown
 *   (4 bytes)  unknown
 *   (4 bytes)  unknown
 *   (4 bytes)  unknown
 *   (4 bytes)  unknown
 *
 *  File
 *   (NULL-termed) file name
 *   (4 bytes)     file uncompressed length
 *   (4 bytes)     file length
 *   (4 bytes)     unknown
 *   (4 bytes)     file directory
 *   (40 bytes)    unknown
 *
 *  Directory
 *   (NULL-termed) file name
 *   (16 bytes)    unknown
 *
 *  ========================================================================
 *
 * Please see the file LICENSE.txt in the source's root directory.
 *
 */

#define __PHYSICSFS_INTERNAL__
#include "physfs_internal.h"

#if PHYSFS_SUPPORTS_RAS

#define RAS_SIG 0x00534152   /* "RAS " in ASCII. */
#define RAS_FULLHEADERLEN 44

#define RAS_ROL(x,y)  ((x<<y) | (x>>(8-y)))

typedef struct
{
    PHYSFS_uint32 filecount;
    PHYSFS_uint32 dircount;
    PHYSFS_uint32 fileinfolen;
    PHYSFS_uint32 dirinfolen;
    PHYSFS_uint32 unknown1; //float32 unknown1;
    PHYSFS_uint32 unknown2;
    PHYSFS_uint32 unknown3;
    PHYSFS_uint32 unknown4;
    PHYSFS_uint32 unknown5;
} RAS_baseinfo;

typedef struct
{
    char* name;
    PHYSFS_uint32 namelen;
} RAS_dir;

typedef struct
{
    char* name;
    PHYSFS_uint32 namelen;
    PHYSFS_uint32 uncompsize;
    PHYSFS_uint32 size;
    PHYSFS_uint32 dir;
    PHYSFS_uint32 offset;
} RAS_file;

typedef enum
{
    RAS_FILE,
    RAS_DIRECTORY
} RasEntryType;

typedef struct _RASentry
{
    char* name;                         /* Name of file in archive        */
    RasEntryType type;
    PHYSFS_uint32 offset;               /* offset of data in archive      */
    PHYSFS_uint32 compressed_size;      /* compressed size                */
    PHYSFS_uint32 uncompressed_size;    /* uncompressed size              */
    struct _RASentry *hashnext;         /* next item in this hash bucket  */
    struct _RASentry *children;         /* linked list of kids, if dir    */
    struct _RASentry *sibling;          /* next item in same dir          */
} RASentry;

typedef struct
{
    PHYSFS_Io *io;            /* the i/o interface for this archive.    */
    RASentry root;            /* root of directory tree.                */
    RASentry **hash;          /* all entries hashed for fast lookup.    */
    size_t hashBuckets;       /* number of buckets in hash.             */
} RASinfo;

typedef struct
{
    PHYSFS_Io *io;
    RASentry *entry;
    PHYSFS_uint32 curPos;
} RASfileinfo;

static PHYSFS_sint64 RAS_read(PHYSFS_Io *io, void *buffer, PHYSFS_uint64 len)
{
    RASfileinfo *finfo = (RASfileinfo *) io->opaque;
    const RASentry *entry = finfo->entry;
    const PHYSFS_uint64 bytesLeft = (PHYSFS_uint64)(entry->compressed_size-finfo->curPos);
    PHYSFS_sint64 rc;

    if (bytesLeft < len)
        len = bytesLeft;

    rc = finfo->io->read(finfo->io, buffer, len);
    if (rc > 0)
        finfo->curPos += (PHYSFS_uint32) rc;

    return rc;
} /* RAS_read */

static PHYSFS_sint64 RAS_write(PHYSFS_Io *io, const void *b, PHYSFS_uint64 len)
{
    BAIL_MACRO(PHYSFS_ERR_READ_ONLY, -1);
} /* RAS_write */

static PHYSFS_sint64 RAS_tell(PHYSFS_Io *io)
{
    return ((RASfileinfo *) io->opaque)->curPos;
} /* RAS_tell */

static int RAS_seek(PHYSFS_Io *io, PHYSFS_uint64 offset)
{
    RASfileinfo *finfo = (RASfileinfo *) io->opaque;
    const RASentry *entry = finfo->entry;
    int rc;

    BAIL_IF_MACRO(offset >= entry->compressed_size, PHYSFS_ERR_PAST_EOF, 0);
    rc = finfo->io->seek(finfo->io, entry->offset + offset);
    if (rc)
        finfo->curPos = (PHYSFS_uint32) offset;

    return rc;
} /* RAS_seek */

static PHYSFS_sint64 RAS_length(PHYSFS_Io *io)
{
    const RASfileinfo *finfo = (RASfileinfo *) io->opaque;
    return ((PHYSFS_sint64) finfo->entry->compressed_size);
} /* RAS_length */

static PHYSFS_Io *RAS_duplicate(PHYSFS_Io *_io)
{
    RASfileinfo *origfinfo = (RASfileinfo *) _io->opaque;
    PHYSFS_Io *io = NULL;
    PHYSFS_Io *retval = (PHYSFS_Io *) allocator.Malloc(sizeof (PHYSFS_Io));
    RASfileinfo *finfo = (RASfileinfo *) allocator.Malloc(sizeof (RASfileinfo));
    GOTO_IF_MACRO(!retval, PHYSFS_ERR_OUT_OF_MEMORY, RAS_duplicate_failed);
    GOTO_IF_MACRO(!finfo, PHYSFS_ERR_OUT_OF_MEMORY, RAS_duplicate_failed);

    io = origfinfo->io->duplicate(origfinfo->io);
    if (!io) goto RAS_duplicate_failed;
    finfo->io = io;
    finfo->entry = origfinfo->entry;
    finfo->curPos = 0;
    memcpy(retval, _io, sizeof (PHYSFS_Io));
    retval->opaque = finfo;
    return retval;

RAS_duplicate_failed:
    if (finfo != NULL) allocator.Free(finfo);
    if (retval != NULL) allocator.Free(retval);
    if (io != NULL) io->destroy(io);
    return NULL;
} /* RAS_duplicate */

static int RAS_flush(PHYSFS_Io *io) { return 1;  /* no write support. */ }

static void RAS_destroy(PHYSFS_Io *io)
{
    RASfileinfo *finfo = (RASfileinfo *) io->opaque;
    finfo->io->destroy(finfo->io);
    allocator.Free(finfo);
    allocator.Free(io);
} /* RAS_destroy */

static const PHYSFS_Io RAS_Io =
{
    CURRENT_PHYSFS_IO_API_VERSION, NULL,
    RAS_read,
    RAS_write,
    RAS_seek,
    RAS_tell,
    RAS_length,
    RAS_duplicate,
    RAS_flush,
    RAS_destroy
};

/*
 * Hash a string for lookup an a RASinfo hashtable.
 */
static inline PHYSFS_uint32 ras_hash_string(const RASinfo *info, const char *s)
{
    return __PHYSFS_hashString(s, strlen(s)) % info->hashBuckets;
} /* ras_hash_string */

/* Find the RASentry for a path in platform-independent notation. */
static RASentry *ras_find_entry(RASinfo *info, const char *path)
{
    PHYSFS_uint32 hashval;
    RASentry *prev = NULL;
    RASentry *retval;

    if (*path == '\0')
        return &info->root;

    hashval = ras_hash_string(info, path);
    for (retval = info->hash[hashval]; retval; retval = retval->hashnext)
    {
        if (strcmp(retval->name, path) == 0)
        {
            if (prev != NULL)  /* move this to the front of the list */
            {
                prev->hashnext = retval->hashnext;
                retval->hashnext = info->hash[hashval];
                info->hash[hashval] = retval;
            } /* if */

            return retval;
        } /* if */

        prev = retval;
    } /* for */

    BAIL_MACRO(PHYSFS_ERR_NOT_FOUND, NULL);
} /* ras_find_entry */

static int ras_hash_entry(RASinfo *info, RASentry *entry);

/* Fill in missing parent directories. */
static RASentry *ras_hash_ancestors(RASinfo *info, char *name)
{
    RASentry *retval = &info->root;
    char *sep = strrchr(name, '/');

    if (sep)
    {
        const size_t namelen = (sep - name);

        *sep = '\0';  /* chop off last piece. */
        retval = ras_find_entry(info, name);
        *sep = '/';

        if (retval != NULL)
        {
            if (retval->type != RAS_DIRECTORY)
                BAIL_MACRO(PHYSFS_ERR_CORRUPT, NULL);
            return retval;  /* already hashed. */
        } /* if */

        /* okay, this is a new dir. Build and hash us. */
        retval = (RASentry *) allocator.Malloc(sizeof (RASentry) + namelen + 1);
        BAIL_IF_MACRO(!retval, PHYSFS_ERR_OUT_OF_MEMORY, NULL);
        memset(retval, '\0', sizeof (*retval));
        retval->name = ((char *) retval) + sizeof (RASentry);
        memcpy(retval->name, name, namelen);
        retval->name[namelen] = '\0';
        retval->type = RAS_DIRECTORY;
        if (!ras_hash_entry(info, retval))
        {
            allocator.Free(retval);
            return NULL;
        } /* if */
    } /* else */

    return retval;
} /* ras_hash_ancestors */

static int ras_hash_entry(RASinfo *info, RASentry *entry)
{
    PHYSFS_uint32 hashval;
    RASentry *parent;

    assert(!ras_find_entry(info, entry->name));  /* checked elsewhere */

    parent = ras_hash_ancestors(info, entry->name);
    if (!parent)
        return 0;

    hashval = ras_hash_string(info, entry->name);
    entry->hashnext = info->hash[hashval];
    info->hash[hashval] = entry;

    entry->sibling = parent->children;
    parent->children = entry;
    return 1;
} /* ras_hash_entry */

static RASentry *ras_load_entry(RAS_file *file)
{
    RASentry* entry;
    entry = (RASentry *) allocator.Malloc(sizeof (RASentry) + file->namelen + 1);
    BAIL_IF_MACRO(entry == NULL, PHYSFS_ERR_OUT_OF_MEMORY, 0);
    entry->name = ((char *) entry) + sizeof (RASentry);
    strncpy(entry->name, file->name, file->namelen);
    entry->name[file->namelen] = '\0';
    if (entry->name[file->namelen - 1] == '/')
    {
        entry->name[file->namelen - 1] = '\0';
        entry->type = RAS_DIRECTORY;
    } /* if */
    else
    {
        entry->type = RAS_FILE;
    }
    entry->offset = file->offset;
    entry->compressed_size = file->size;
    entry->uncompressed_size = file->uncompsize;
    entry->children = NULL;
    entry->sibling = NULL;
    return entry;
} /* ras_load_entry */

static int ras_load_entries(RASinfo *info, PHYSFS_uint32 fileCount, RAS_file* files)
{
    PHYSFS_uint32 i;

    for (i = 0; i < fileCount; i++)
    {
        RASentry *entry = ras_load_entry(&files[i]);
        RASentry *find;

        find = ras_find_entry(info, entry->name);
        if (find != NULL)  /* duplicate? */
        {
            find->offset = entry->offset;
            find->compressed_size = entry->compressed_size;
            find->uncompressed_size = entry->uncompressed_size;
            allocator.Free(entry);
            continue;
        } /* if */

        if (!ras_hash_entry(info, entry))
        {
            allocator.Free(entry);
            return 0;
        } /* if */
    }
    return 1;
} /* ras_load_entries */

static void ras_decrypt(char* data, PHYSFS_uint32 length, PHYSFS_sint32 seed)
{
    if (seed == 0)
        seed = 1;

    if (length > 0) {
        PHYSFS_sint32 pos;
        for (pos = 0; pos < length; pos++) {
            data[pos] = (PHYSFS_uint8) RAS_ROL((PHYSFS_uint8 )data[pos], (PHYSFS_uint8 )(pos % 5));

            PHYSFS_sint32 edx = ((PHYSFS_sint32) (((PHYSFS_sint64) seed * (PHYSFS_sint32) 0xb92143fb) >> 32) + seed) >> 7;
            seed = (seed * 0xab) - ((((PHYSFS_uint32) edx >> 0x1f) + edx) * 0x763d);

            data[pos] = ((((PHYSFS_uint8) pos + 3) * 6) ^ data[pos]) + (PHYSFS_uint8) seed;
        }
    }
}

static RAS_dir* RAS_loadDirs(char* data, PHYSFS_uint32 datalen, PHYSFS_uint32 dircount)
{
    RAS_dir* dirs = (RAS_dir *) allocator.Malloc(sizeof (RAS_dir) * dircount);

    PHYSFS_uint32 ptr = 0;
    PHYSFS_uint32 dirindex;
    for (dirindex = 0; dirindex < dircount; dirindex++) {
        PHYSFS_uint32 baseptr = ptr;
        RAS_dir dir;
        while (ptr < datalen && data[ptr] != 0) {
            ptr++;
        }
        if(ptr > baseptr && data[baseptr] == '\\')
            baseptr++;
        PHYSFS_uint32 nameend = ptr;
        ptr = baseptr;
        PHYSFS_uint32 namelen = nameend - baseptr;
        char* name = (char *) allocator.Malloc(sizeof (char) * (namelen + 1));
        while (ptr < nameend) {
            name[ptr - baseptr] = (data[ptr] == '\\') ? '/' : data[ptr];
            ptr++;
        }
        name[namelen] = '\0';
        dir.name = name;
        dir.namelen = namelen;
        ptr++;
        ptr += sizeof(PHYSFS_uint32) + sizeof(PHYSFS_uint16) * 6;
        dirs[dirindex] = dir;
    }
    return dirs;
}

static RAS_file* RAS_loadFiles(char* data, PHYSFS_uint32 datalen, PHYSFS_uint32 filecount, RAS_dir* dirs, PHYSFS_uint32 dircount, PHYSFS_uint32 offset)
{
    RAS_file* files = (RAS_file *) allocator.Malloc(sizeof (RAS_file) * filecount);
    RAS_file* f = files;
    PHYSFS_uint32 ptr = 0;
    PHYSFS_uint32 fileindex;
    for (fileindex = 0; fileindex < filecount; fileindex++) {
        PHYSFS_uint32 baseptr = ptr;
        while (ptr < datalen && data[ptr] != 0) {
            ptr++;
        }
        PHYSFS_uint32 nameend = ptr;
        ptr = baseptr;
        PHYSFS_uint32 namelen = nameend - baseptr;
        char* name = (char *) allocator.Malloc(sizeof (char) * (namelen + 1));
        while (ptr < nameend) {
            name[ptr - baseptr] = data[ptr];
            ptr++;
        }
        name[namelen] = '\0';
        ptr++;
        f->uncompsize = *((PHYSFS_uint32*) (data + ptr));
        f->size = *((PHYSFS_uint32*) (data + ptr + sizeof(PHYSFS_uint32)));
        f->dir = *((PHYSFS_uint32*) (data + ptr + sizeof(PHYSFS_uint32) * 3));
        f->namelen = dirs[f->dir].namelen + namelen;
        f->name = (char *) allocator.Malloc(sizeof (char) * (f->namelen + 1));
        strncpy(f->name, dirs[f->dir].name, dirs[f->dir].namelen + 1);
        strncat(f->name, name, namelen);
        f->name[f->namelen] = '\0';
        f->offset = offset;
        offset += f->size;
        ptr += sizeof(PHYSFS_uint32) * 7 + sizeof(PHYSFS_uint16) * 6;

        f++;
        allocator.Free(name);
    }
    return files;
}

static int ras_alloc_hashtable(RASinfo *info, const PHYSFS_uint64 entry_count)
{
    size_t alloclen;

    info->hashBuckets = (size_t) (entry_count / 5);
    if (!info->hashBuckets)
        info->hashBuckets = 1;

    alloclen = info->hashBuckets * sizeof (RASentry *);
    info->hash = (RASentry **) allocator.Malloc(alloclen);
    BAIL_IF_MACRO(!info->hash, PHYSFS_ERR_OUT_OF_MEMORY, 0);
    memset(info->hash, '\0', alloclen);

    return 1;
} /* ras_alloc_hashtable */

static void RAS_closeArchive(void *opaque);

static void *RAS_openArchive(PHYSFS_Io *io, const char *name, int forWriting)
{
    RASinfo *info = NULL;
    PHYSFS_uint32 val = 0;
    PHYSFS_sint32 seed = 0;
    RAS_baseinfo binfo;

    assert(io != NULL);  /* shouldn't ever happen. */

    BAIL_IF_MACRO(forWriting, PHYSFS_ERR_READ_ONLY, NULL);

    BAIL_IF_MACRO(!__PHYSFS_readAll(io, &val, 4), ERRPASS, NULL);
    if (PHYSFS_swapULE32(val) != RAS_SIG)
        BAIL_MACRO(PHYSFS_ERR_UNSUPPORTED, NULL);

    info = (RASinfo *) allocator.Malloc(sizeof (RASinfo));
    BAIL_IF_MACRO(!info, PHYSFS_ERR_OUT_OF_MEMORY, NULL);
    memset(info, '\0', sizeof (RASinfo));
    info->io = io;
    info->root.type = RAS_DIRECTORY;

    BAIL_IF_MACRO(!__PHYSFS_readAll(io, &seed, 4), ERRPASS, NULL);

    BAIL_IF_MACRO(!__PHYSFS_readAll(io, &binfo, sizeof(RAS_baseinfo)), ERRPASS, NULL);
    ras_decrypt((char*) &binfo, sizeof(RAS_baseinfo), seed);

    char* fileinfodata = (char *) allocator.Malloc(sizeof (char) * binfo.fileinfolen);
    BAIL_IF_MACRO(!__PHYSFS_readAll(io, fileinfodata, binfo.fileinfolen), ERRPASS, NULL);
    ras_decrypt(fileinfodata, binfo.fileinfolen, seed);

    char* dirinfodata = (char *) allocator.Malloc(sizeof (char) * binfo.dirinfolen);
    BAIL_IF_MACRO(!__PHYSFS_readAll(io, dirinfodata, binfo.dirinfolen), ERRPASS, NULL);
    ras_decrypt(dirinfodata, binfo.dirinfolen, seed);

    RAS_dir* dirs = RAS_loadDirs(dirinfodata, binfo.dirinfolen, binfo.dircount);
    RAS_file* files = RAS_loadFiles(fileinfodata, binfo.fileinfolen, binfo.filecount, dirs, binfo.dircount, RAS_FULLHEADERLEN + binfo.fileinfolen + binfo.dirinfolen);

    allocator.Free(fileinfodata);
    allocator.Free(dirinfodata);

    if(!ras_alloc_hashtable(info, binfo.dircount + binfo.filecount))
        goto RAS_openarchive_failed;
    else if (!ras_load_entries(info, binfo.filecount, files))
        goto RAS_openarchive_failed;

    PHYSFS_uint32 fileindex;
    for (fileindex = 0; fileindex < binfo.filecount; fileindex++) {
        allocator.Free(files[fileindex].name);
    }
    allocator.Free(files);

    PHYSFS_uint32 dirindex;
    for (dirindex = 0; dirindex < binfo.dircount; dirindex++) {
        allocator.Free(dirs[dirindex].name);
    }
    allocator.Free(dirs);

    assert(info->root.sibling == NULL);
    return info;

RAS_openarchive_failed:
    info->io = NULL;  /* don't let RAS_closeArchive destroy (io). */

    RAS_closeArchive(info);
    return NULL;
} /* RAS_openArchive */


static void RAS_enumerateFiles(void *opaque, const char *dname,
                               PHYSFS_EnumFilesCallback cb,
                               const char *origdir, void *callbackdata)
{
    RASinfo *info = ((RASinfo *) opaque);
    const RASentry *entry = ras_find_entry(info, dname);
    if (entry && (entry->type == RAS_DIRECTORY))
    {
        for (entry = entry->children; entry; entry = entry->sibling)
        {
            const char *ptr = strrchr(entry->name, '/');
            cb(callbackdata, origdir, ptr ? ptr + 1 : entry->name);
        } /* for */
    } /* if */
} /* RAS_enumerateFiles */


static PHYSFS_Io *RAS_openRead(void *opaque, const char *name)
{
    PHYSFS_Io *retval = NULL;
    RASinfo *info = (RASinfo *) opaque;
    RASfileinfo *finfo = NULL;

    RASentry *entry = ras_find_entry(info, name);

    GOTO_IF_MACRO(!entry, ERRPASS, RAS_openRead_failed);
    GOTO_IF_MACRO(entry->type == RAS_DIRECTORY, PHYSFS_ERR_NOT_A_FILE, RAS_openRead_failed);

    retval = (PHYSFS_Io *) allocator.Malloc(sizeof (PHYSFS_Io));
    GOTO_IF_MACRO(!retval, PHYSFS_ERR_OUT_OF_MEMORY, RAS_openRead_failed);

    finfo = (RASfileinfo *) allocator.Malloc(sizeof (RASfileinfo));
    GOTO_IF_MACRO(!finfo, PHYSFS_ERR_OUT_OF_MEMORY, RAS_openRead_failed);

    finfo->io = info->io->duplicate(info->io);
    GOTO_IF_MACRO(!finfo->io, ERRPASS, RAS_openRead_failed);

    if (!finfo->io->seek(finfo->io, entry->offset))
        goto RAS_openRead_failed;

    finfo->curPos = 0;
    finfo->entry = entry;

    memcpy(retval, &RAS_Io, sizeof (*retval));
    retval->opaque = finfo;
    return retval;

RAS_openRead_failed:
    if (finfo != NULL)
    {
        if (finfo->io != NULL)
            finfo->io->destroy(finfo->io);
        allocator.Free(finfo);
    } /* if */

    if (retval != NULL)
        allocator.Free(retval);

    return NULL;
} /* UNPK_openRead */

static PHYSFS_Io *RAS_openWrite(void *opaque, const char *filename)
{
    BAIL_MACRO(PHYSFS_ERR_READ_ONLY, NULL);
} /* RAS_openWrite */

static PHYSFS_Io *RAS_openAppend(void *opaque, const char *filename)
{
    BAIL_MACRO(PHYSFS_ERR_READ_ONLY, NULL);
} /* RAS_openAppend */

static int RAS_remove(void *opaque, const char *name)
{
    BAIL_MACRO(PHYSFS_ERR_READ_ONLY, 0);
} /* RAS_remove */


static int RAS_mkdir(void *opaque, const char *name)
{
    BAIL_MACRO(PHYSFS_ERR_READ_ONLY, 0);
} /* RAS_mkdir */

static int RAS_stat(void *opaque, const char *filename, PHYSFS_Stat *stat)
{
    RASinfo *info = (RASinfo *) opaque;
    const RASentry *entry = ras_find_entry(info, filename);

    /* !!! FIXME: does this need to resolve entries here? */

    if (entry == NULL)
        return 0;

    else if (entry->type == RAS_DIRECTORY)
    {
        stat->filesize = 0;
        stat->filetype = PHYSFS_FILETYPE_DIRECTORY;
    } /* if */
    else
    {
        //stat->filesize = (PHYSFS_sint64) entry->uncompressed_size;
        stat->filesize = (PHYSFS_sint64) entry->compressed_size;
        stat->filetype = PHYSFS_FILETYPE_REGULAR;
    } /* else */

    stat->modtime = 0;
    stat->createtime = 0;
    stat->accesstime = 0;
    stat->readonly = 1; /* .ras files are always read only */

    return 1;
} /* RAS_stat */

void RAS_closeArchive(void *opaque)
{
    RASinfo *info = ((RASinfo *) opaque);

    if (!info)
        return;

    if (info->io)
        info->io->destroy(info->io);

    assert(info->root.sibling == NULL);
    assert(info->hash || (info->root.children == NULL));

    if (info->hash)
    {
        size_t i;
        for (i = 0; i < info->hashBuckets; i++)
        {
            RASentry *entry;
            RASentry *next;
            for (entry = info->hash[i]; entry; entry = next)
            {
                next = entry->hashnext;
                allocator.Free(entry);
            } /* for */
        } /* for */
        allocator.Free(info->hash);
    } /* if */

    allocator.Free(info);
} /* RAS_closeArchive */

const PHYSFS_Archiver __PHYSFS_Archiver_RAS =
{
    CURRENT_PHYSFS_ARCHIVER_API_VERSION,
    {
        "RAS",
        "Max Payne 2 format",
        "Johannes Hackel",
        "https://icculus.org/physfs/",
        0,  /* supportsSymlinks */
    },
    RAS_openArchive,
    RAS_enumerateFiles,
    RAS_openRead,
    RAS_openWrite,
    RAS_openAppend,
    RAS_remove,
    RAS_mkdir,
    RAS_stat,
    RAS_closeArchive
};

#endif  /* defined PHYSFS_SUPPORTS_RAS */

/* end of archiver_ras.c ... */

