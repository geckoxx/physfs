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

#define RAS_ROL(x,y)  ((x<<y) | (x>>(8-y)))

typedef struct RAS_baseinfo {
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

typedef struct RAS_dir {
    char* name;
    PHYSFS_uint32 namelen;
} RAS_dir;

typedef struct RAS_file {
    char* name;
    PHYSFS_uint32 namelen;
    PHYSFS_uint32 uncompsize;
    PHYSFS_uint32 size;
    PHYSFS_uint32 dir;
    PHYSFS_uint32 offset;
} RAS_file;

static UNPKentry *rasLoadEntries(PHYSFS_Io *io, PHYSFS_uint32 dirCount, RAS_dir* dirs, PHYSFS_uint32 fileCount, RAS_file* files)
{
    UNPKentry *entries = NULL;
    UNPKentry *entry = NULL;

    entries = (UNPKentry *) allocator.Malloc(sizeof (UNPKentry) * fileCount);
    BAIL_IF_MACRO(entries == NULL, PHYSFS_ERR_OUT_OF_MEMORY, NULL);

    char* name = (char *) allocator.Malloc(sizeof entry->name);
    for (entry = entries; fileCount > 0; fileCount--, entry++)
    {
        RAS_file* file = files + fileCount - 1;
        strncpy(name, dirs[file->dir].name + 1, dirs[file->dir].namelen);
        strncat(name, file->name, file->namelen);
        name[file->namelen + dirs[file->dir].namelen] = '\0';
        strncpy(entry->name, name, sizeof entry->name - 1);
        entry->startPos = file->offset;
        entry->size = file->size;
    } /* for */

    allocator.Free(name);

    return entries;
} /* rasLoadEntries */

static void RAS_decrypt(char* data, PHYSFS_uint32 length, PHYSFS_sint32 seed)
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

static RAS_file* RAS_loadFiles(char* data, PHYSFS_uint32 datalen, PHYSFS_uint32 filecount, PHYSFS_uint32 offset)
{
    RAS_file* files = (RAS_file *) allocator.Malloc(sizeof (RAS_file) * filecount);

    PHYSFS_uint32 ptr = 0;
    PHYSFS_uint32 fileindex;
    for (fileindex = 0; fileindex < filecount; fileindex++) {
        PHYSFS_uint32 baseptr = ptr;
        RAS_file f;
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
        f.name = name;
        f.namelen = namelen;
        ptr++;
        f.uncompsize = *((PHYSFS_uint32*) (data + ptr));
        f.size = *((PHYSFS_uint32*) (data + ptr + sizeof(PHYSFS_uint32)));
        f.dir = *((PHYSFS_uint32*) (data + ptr + sizeof(PHYSFS_uint32) * 3));
        f.offset = offset;
        offset += f.size;
        ptr += sizeof(PHYSFS_uint32) * 7 + sizeof(PHYSFS_uint16) * 6;
        files[fileindex] = f;
    }
    return files;
}

static void *RAS_openArchive(PHYSFS_Io *io, const char *name, int forWriting)
{
    UNPKentry *entries = NULL;
    PHYSFS_uint32 val = 0;
    PHYSFS_sint32 seed = 0;
    RAS_baseinfo binfo;

    assert(io != NULL);  /* shouldn't ever happen. */

    BAIL_IF_MACRO(forWriting, PHYSFS_ERR_READ_ONLY, NULL);

    BAIL_IF_MACRO(!__PHYSFS_readAll(io, &val, 4), ERRPASS, NULL);
    if (PHYSFS_swapULE32(val) != RAS_SIG)
        BAIL_MACRO(PHYSFS_ERR_UNSUPPORTED, NULL);

    BAIL_IF_MACRO(!__PHYSFS_readAll(io, &seed, 4), ERRPASS, NULL);

    BAIL_IF_MACRO(!__PHYSFS_readAll(io, &binfo, sizeof(RAS_baseinfo)), ERRPASS, NULL);
    RAS_decrypt((char*) &binfo, sizeof(RAS_baseinfo), seed);

    char* fileinfodata = (char *) allocator.Malloc(sizeof (char) * binfo.fileinfolen);
    BAIL_IF_MACRO(!__PHYSFS_readAll(io, fileinfodata, binfo.fileinfolen), ERRPASS, NULL);
    RAS_decrypt(fileinfodata, binfo.fileinfolen, seed);

    char* dirinfodata = (char *) allocator.Malloc(sizeof (char) * binfo.dirinfolen);
    BAIL_IF_MACRO(!__PHYSFS_readAll(io, dirinfodata, binfo.dirinfolen), ERRPASS, NULL);
    RAS_decrypt(dirinfodata, binfo.dirinfolen, seed);

    RAS_file* files = RAS_loadFiles(fileinfodata, binfo.fileinfolen, binfo.filecount, 44 + binfo.fileinfolen + binfo.dirinfolen);
    RAS_dir* dirs = RAS_loadDirs(dirinfodata, binfo.dirinfolen, binfo.dircount);

    allocator.Free(fileinfodata);
    allocator.Free(dirinfodata);

    entries = rasLoadEntries(io, binfo.dircount, dirs, binfo.filecount, files);

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

    BAIL_IF_MACRO(!entries, ERRPASS, NULL);
    return UNPK_openArchive(io, entries, binfo.filecount);
} /* RAS_openArchive */


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
    UNPK_enumerateFiles,
    UNPK_openRead,
    UNPK_openWrite,
    UNPK_openAppend,
    UNPK_remove,
    UNPK_mkdir,
    UNPK_stat,
    UNPK_closeArchive
};

#endif  /* defined PHYSFS_SUPPORTS_RAS */

/* end of archiver_ras.c ... */

