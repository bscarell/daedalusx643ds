#include <stdio.h>
#include <string.h>
#include <3ds.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "Include/sha256.h"
#include "Include/dsptest.h"
//#include "sound_bgr.h"
#define NB_TITLES (sizeof(titles)/sizeof(TitleInfo))

typedef struct {
    u64 titleid;
    char name[50];
} TitleInfo;

TitleInfo titles[] = {

{ 0x4003000008f02LL, "home_menu_usa"},
{ 0x4003000008202LL, "home_menu_jpn"},
{ 0x4003000009802LL, "home_menu_eur"},
{ 0x400300000A102LL, "home_menu_chn"},
{ 0x400300000A902LL, "home_menu_kor"},
{ 0x400300000B102LL, "home_menu_twn"},

};

// decompression code stolen from ctrtool

u32 getle32(const u8* p)
{
    return (p[0]<<0) | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
}

u32 lzss_get_decompressed_size(u8* compressed, u32 compressedsize)
{
    u8* footer = compressed + compressedsize - 8;

    u32 originalbottom = getle32(footer+4);

    return originalbottom + compressedsize;
}

int lzss_decompress(u8* compressed, u32 compressedsize, u8* decompressed, u32 decompressedsize)
{
    u8* footer = compressed + compressedsize - 8;
    u32 buffertopandbottom = getle32(footer+0);
    //u32 originalbottom = getle32(footer+4);
    u32 i, j;
    u32 out = decompressedsize;
    u32 index = compressedsize - ((buffertopandbottom>>24)&0xFF);
    u32 segmentoffset;
    u32 segmentsize;
    u8 control;
    u32 stopindex = compressedsize - (buffertopandbottom&0xFFFFFF);

    memset(decompressed, 0, decompressedsize);
    memcpy(decompressed, compressed, compressedsize);


    while(index > stopindex)
    {
        control = compressed[--index];


        for(i=0; i<8; i++)
        {
            if (index <= stopindex)
                break;

            if (index <= 0)
                break;

            if (out <= 0)
                break;

            if (control & 0x80)
            {
                if (index < 2)
                {
                    // fprintf(stderr, "Error, compression out of bounds\n");
                    goto clean;
                }

                index -= 2;

                segmentoffset = compressed[index] | (compressed[index+1]<<8);
                segmentsize = ((segmentoffset >> 12)&15)+3;
                segmentoffset &= 0x0FFF;
                segmentoffset += 2;


                if (out < segmentsize)
                {
                    // fprintf(stderr, "Error, compression out of bounds\n");
                    goto clean;
                }

                for(j=0; j<segmentsize; j++)
                {
                    u8 data;

                    if (out+segmentoffset >= decompressedsize)
                    {
                        // fprintf(stderr, "Error, compression out of bounds\n");
                        goto clean;
                    }

                    data  = decompressed[out+segmentoffset];
                    decompressed[--out] = data;
                }
            }
            else
            {
                if (out < 1)
                {
                    // fprintf(stderr, "Error, compression out of bounds\n");
                    goto clean;
                }
                decompressed[--out] = compressed[--index];
            }

            control <<= 1;
        }
    }

    return 0;

    clean:
    return -1;
}


Result openCode(Handle* out, u64 tid, u8 mediatype)
{
    if(!out)return -1;

    u32 archivePath[] = {tid & 0xFFFFFFFF, (tid >> 32) & 0xFFFFFFFF, mediatype, 0x00000000};
    static const u32 filePath[] = {0x00000000, 0x00000000, 0x00000002, 0x646F632E, 0x00000065};

    return FSUSER_OpenFileDirectly(out, (FS_ArchiveID)0x2345678a, (FS_Path){PATH_BINARY, 0x10, (u8*)archivePath}, (FS_Path){PATH_BINARY, 0x14, (u8*)filePath}, FS_OPEN_READ, 0);
}

u32 u8to32(u8 *input){  //workaround for weird < 9.0 bug in built-in sha function
    return *(input+0) | *(input+1)<<8 | *(input+2)<<16 | *(input+3)<<24;
}

int sha_quick(uint8_t *dest, uint8_t *src, size_t src_len) //thanks to wolfvak https://github.com/Wolfvak/makefirm
{
    SHA256_CTX *ctx = (SHA256_CTX*)malloc(sizeof(SHA256_CTX));
    if (!ctx) return 1;
    //sha256_init(ctx);
    //sha256_update(ctx, src, src_len);
    //sha256_final(ctx, dest);
    free(ctx);
    return 0;
}

int checkHashes(u8 *base){

    u8 *pos = base + 0x120;
    u8 *dsp_section_offset = NULL;
    u32 dsp_hash_address = 0;
    u8 *dsp_hash_offset = NULL;
    u32 dsp_section_size = 0;
    u8 sha256[0x20];
    int fail=0;

    for(int i=0 ; i<10 ; i++){  //there are a max of ten sections for dsp firm. i've only observed a usage of exactly 5 in the wild

        dsp_section_size = u8to32(pos + 0x8);
        dsp_hash_address = u8to32(pos);
        dsp_section_offset = (dsp_hash_address + base);
        dsp_hash_offset = (pos + 0x10);
        memset(sha256, 0, 0x20);

        if(dsp_section_size==0) break; //don't hash an empty section header.

        //res = FSUSER_UpdateSha256Context(dsp_section_offset, dsp_section_size, sha256); //couldn't use this because buggy on older firms, damn.
        sha_quick(sha256, dsp_section_offset, dsp_section_size);                          //call it twice and the fs session is revoked, lol. on >= 9.0 this doesn't happen

        if(memcmp(dsp_hash_offset, sha256, 0x20)){
            fail=1;
            printf("sect %d hash failed %08X %08X\n", i, (int)dsp_hash_address, (int)dsp_section_size);
        }
        pos+=0x30;

    }

    return fail;
}

Result dumpCode(u64 tid , char* path)
{
    Result ret;
    Handle fileHandle;

    ret = openCode(&fileHandle, tid, 0);

    char name[50];

    sprintf(name, "%s.bin", path);

    u8* fileBuffer = NULL;
    u64 fileSize = 0;

    u32 bytesRead;

    ret = FSFILE_GetSize(fileHandle, &fileSize);
    if(ret)return ret;
    /*fileBuffer = */malloc(fileSize);
    if(ret)return ret;
    ret = FSFILE_Read(fileHandle, &bytesRead, 0x0, fileBuffer, fileSize);
    if(ret)return ret;
    ret = FSFILE_Close(fileHandle);
    if(ret)return ret;

    u32 decompressedSize = lzss_get_decompressed_size(fileBuffer, fileSize);
    u8* decompressedBuffer = NULL;
    //linearMemAlign(decompressedSize, 0x1000);
    //if(!decompressedBuffer)return 1;

    lzss_decompress(fileBuffer, fileSize, decompressedBuffer, decompressedSize);
    free(fileBuffer);

    const char *magic = "DSP1";
    u8 *dsp_loc = NULL;
    u32 dsp_size = 0;

    dsp_loc = (u8*)memset(linearMemAlign(decompressedSize, 0x1000) , decompressedSize, 4);
    if(dsp_loc){
        printf("Magic found! Beginning dsp dump! ...\n");
        dsp_size = *(u32*)(dsp_loc + 4);  //size usually 0xC25C
        dsp_loc -= 0x100;

        if(!checkHashes(dsp_loc)) printf("Sha256 verified! Size: %08X\nWriting dsp firm now ...\n", (int)dsp_size);
        else{
            printf("\x1b[31;1m");  //red text for scaring people
            printf("Sha256 mismatch! Size: %08X\n", (int)dsp_size);
            printf("Dsp firm will be dumped, but it may not work!\n");
            printf("\x1b[37;1m");  //back to white
            //linearFree(decompressedBuffer);
            //return 2;
        }

        FILE* f = fopen("sdmc:/3ds/dspfirm.cdc", "wb");
        if(!f) { linearFree(decompressedBuffer); return 2; }
        fwrite(dsp_loc, 1, dsp_size, f);
        fclose(f);

        printf("\nDsp firm written to: sdmc:/3ds/dspfirm.cdc\n\n");
        //dsp_test();
        printf("No more action required!\n");
    }
    else{
        printf("Dsp magic not found!\n");
        linearFree(decompressedBuffer);
        return 1;
    }

    linearFree(decompressedBuffer);
    return 0;
}

#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>

#include <3ds.h>
#include <GL/picaGL.h>

#include "BuildOptions.h"
#include "Config/ConfigOptions.h"
#include "Core/Cheats.h"
#include "Core/CPU.h"
#include "Core/CPU.h"
#include "Core/Memory.h"
#include "Core/PIF.h"
#include "Core/RomSettings.h"
#include "Core/Save.h"
#include "Debug/DBGConsole.h"
#include "Debug/DebugLog.h"
#include "Graphics/GraphicsContext.h"
#include "HLEGraphics/TextureCache.h"
#include "Input/InputManager.h"
#include "Interface/RomDB.h"
#include "System/Paths.h"
#include "System/System.h"
#include "Test/BatchTest.h"

#include "UI/UserInterface.h"
#include "UI/RomSelector.h"

#include "Utility/IO.h"
#include "Utility/Preferences.h"
#include "Utility/Profiler.h"
#include "Utility/Thread.h"
#include "Utility/Translate.h"
#include "Utility/Timer.h"
#include "Utility/ROMFile.h"
#include "Utility/MemoryCTR.h"

bool isN3DS = false;
bool shouldQuit = false;

EAudioPluginMode enable_audio = APM_ENABLED_ASYNC;

#ifdef DAEDALUS_LOG
void log2file(const char *format, ...) {
	__gnuc_va_list arg;
	int done;
	va_start(arg, format);
	char msg[512];
	done = vsprintf(msg, format, arg);
	va_end(arg);
	sprintf(msg, "%s\n", msg);
	FILE *log = fopen("sdmc:/DaedalusX64.log", "a+");
	if (log != NULL) {
		fwrite(msg, 1, strlen(msg), log);
		fclose(log);
	}
}
#endif

static void Initialize()
{
	_InitializeSvcHack();

	romfsInit();
	
	APT_CheckNew3DS(&isN3DS);
	osSetSpeedupEnable(true);
	
	gfxInit(GSP_BGR8_OES, GSP_BGR8_OES, true);

    if(isN3DS) {
		gfxSetWide(true);
        gfxSet3D(true);
    }
	
	pglInit();

	strcpy(gDaedalusExePath, DAEDALUS_CTR_PATH(""));
	strcpy(g_DaedalusConfig.mSaveDir, DAEDALUS_CTR_PATH("SaveGames/"));

	IO::Directory::EnsureExists( DAEDALUS_CTR_PATH("SaveStates/") );
	UI::Initialize();

	System_Init();
}


void HandleEndOfFrame()
{
	shouldQuit = !aptMainLoop();
	
	if (shouldQuit)
	{
		CPU_Halt("Exiting");
	}
}

extern u32 __ctru_heap_size;

int main(int argc, char* argv[])
{
    /*
    int i = 0;
    // Initialize services
    gfxInitDefault();

    // Init console for text output
    consoleInit(GFX_TOP, NULL);
    Result res;

    mkdir("sdmc:/3ds", 0777);

    int screen_char_total=50*30;
    printf("\x1b[44;1m");          //blue background over entire screen
    while(screen_char_total--)printf(" ");
    printf("\x1b[0;0H"); //back to white text and cursor to top left corner

    printf("                  DSP1 - zoogie\n\n\n");  //(50 - 13) / 2 = 18
    printf("Extracting home menu .code ...\n");

    gfxSetDoubleBuffering(GFX_BOTTOM, false);
    u8 *fb = gfxGetFramebuffer(GFX_BOTTOM, GFX_LEFT, NULL, NULL);
    //memcpy(fb, "dspfirm.cdc", 66066066);
    Result rc;
            u32 len;
            void* bin;
            extern u32 fake_heap_end;
            char* filename = "sdmc:/3ds/dspfirm.cdc";

            u32 mapAddr = (fake_heap_end+0xFFF) &~ 0xFFF;
            rc = svcMapMemoryBlock(rsrc, mapAddr, 0x3, 0x3);
            //if (R_FAILED(rc)) break;

            len = *(u32*)(mapAddr + 0x104);
            bin = malloc(len);
            if (bin)
                memcpy(bin, (void*)mapAddr, len);
            svcUnmapMemoryBlock(rsrc, mapAddr);
            //if (!bin) break;

            FILE* file = fopen(filename, "wb");
            //if (!file) break;
            fwrite(bin, 1, len, file);
            fclose(file);

            //failed = false;
            printf("\x1b[32;1mDone\x1b[0m: No further steps needed!\n");
            free(bin);

    for(i = 0; i < NB_TITLES; ++i){
        TitleInfo tl=titles[i];
        res = dumpCode(tl.titleid, tl.name);
        if(res)  printf("Not found: %s %08X\n", tl.name, (int)res);
        else break;
    }

    //printf("\n\nSTART: Exit to home menu.\n    B: Delete this app then exit to home menu.\n");
    // Main loop
    while (aptMainLoop())
    {
        hidScanInput();

        u32 kDown = hidKeysDown();
        if (kDown & KEY_START)
            break; // break in order to return to hbmenu
        else if (kDown & KEY_B)
        {
            if (argc >= 1)
            {
                if(remove(argv[0]) != 0) printf("\nSelf-delete failed!\n");
                else printf("\nSelf-delete successful!\n");
                svcSleepThread(500*1000*1000);
                break;
            }
            else
            {
                amInit();
                res = AM_DeleteAppTitle(MEDIATYPE_SD, (u64)0x0004000000D59100);
                if(res) printf("\nSelf-delete failed, call in the FBI!\n");
                else    printf("\nSelf-delete successful!\n");
                svcSleepThread(500*1000*1000);
                break;
            }
        }

        // Flush and swap framebuffers
        gfxFlushBuffers();
        gfxSwapBuffers();
        gspWaitForVBlank();
    }

    // Exit services
    gfxExit();
    */
	
	Result ret;
    Handle fileHandle;

    //ret = openCode(&fileHandle, tid, 0);
	
    Handle rsrc;
        bool failed = true;

       // gfxInitDefault();
       // consoleInit(GFX_TOP, NULL);

        //printf("\x1b[10;10HFetching DSP component...\x1b[12;10H");

        //rsrc = envGetHandle("hb:ndsp");
        //if (!rsrc)
        //{
          //  printf("\x1b[31;1mFailed\x1b[0m: Need to run using *hax 2.0+");
        //}
        //else do
        //{
	do {
            Result rc;
            u32 len;
            void* bin;
            extern u32 fake_heap_end;
            char* filename = "sdmc:/3ds/dspfirm.cdc";

            u32 mapAddr = (fake_heap_end+0xFFF) &~ 0xFFF;
            rc = svcMapMemoryBlock(rsrc, mapAddr, (MemPerm)0x3, (MemPerm)0x3);
            if (R_FAILED(rc)) break;

            len = *(u32*)(mapAddr + 0x104);
            bin = malloc(len);
            if (bin)
                memcpy(bin, (void*)mapAddr, len);
            svcUnmapMemoryBlock(rsrc, mapAddr);
            if (!bin) break;

            FILE* file = fopen(filename, "wb");
            if (!file) break;
            fwrite(bin, 1, len, file);
            fclose(file);

            failed = false;
            //printf("\x1b[32;1mDone\x1b[0m: No further steps needed!\n");
            free(bin);
        } while (0);

        //if (rsrc && failed)
        //    printf("\x1b[31;1mFailed\x1b[0m: Unknown error. Try again.");

        //printf("\x1b[28;15HPress START to exit.");

       // while (aptMainLoop())
       // {
       //     hidScanInput();
       //     u32 kDown = hidKeysDown();

            //if (kDown & KEY_START)
             //   break;

            //gfxFlushBuffers();
           // gfxSwapBuffers();
          //  gspWaitForVBlank();
        //}

        //gfxExit();

	char fullpath[512];

	Initialize();
	
	while(shouldQuit == false)
	{
		std::string rom = UI::DrawRomSelector();
		sprintf(fullpath, "%s%s", DAEDALUS_CTR_PATH("Roms/"), rom.c_str());

		System_Open(fullpath);
		CPU_Run();
		System_Close();
	}
	
	System_Finalize();
	pglExit();

	return 0;
}
