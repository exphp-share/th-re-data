struct IUnknownVtbl
{
    void* QueryInterface;
    void* AddRef;
    void* Release;
};

struct IDirect3D8Vtbl {
    struct IUnknownVtbl super;
    void* RegisterSoftwareDevice;
    void* GetAdapterCount;
    void* GetAdapterIdentifier;
    void* GetAdapterModeCount;
    void* EnumAdapterModes;
    void* GetAdapterDisplayMode;
    void* CheckDeviceType;
    void* CheckDeviceFormat;
    void* CheckDeviceMultiSampleType;
    void* CheckDepthStencilMatch;
    void* GetDeviceCaps;
    void* GetAdapterMonitor;
    void* CreateDevice;
};

struct IDirect3DDevice8Vtbl {
    struct IUnknownVtbl super;
    void* TestCooperativeLevel;
    void* GetAvailableTextureMem;
    void* ResourceManagerDiscardBytes;
    void* GetDirect3D;
    void* GetDeviceCaps;
    void* GetDisplayMode;
    void* GetCreationParameters;
    void* SetCursorProperties;
    void* SetCursorPosition;
    void* ShowCursor;
    void* CreateAdditionalSwapChain;
    void* Reset;
    void* Present;
    void* GetBackBuffer;
    void* GetRasterStatus;
    void* SetGammaRamp;
    void* GetGammaRamp;
    void* CreateTexture;
    void* CreateVolumeTexture;
    void* CreateCubeTexture;
    void* CreateVertexBuffer;
    void* CreateIndexBuffer;
    void* CreateRenderTarget;
    void* CreateDepthStencilSurface;
    void* CreateImageSurface;
    void* CopyRects;
    void* UpdateTexture;
    void* GetFrontBuffer;
    void* SetRenderTarget;
    void* GetRenderTarget;
    void* GetDepthStencilSurface;
    void* BeginScene;
    void* EndScene;
    void* Clear;
    void* SetTransform;
    void* GetTransform;
    void* MultiplyTransform;
    void* SetViewport;
    void* GetViewport;
    void* SetMaterial;
    void* GetMaterial;
    void* SetLight;
    void* GetLight;
    void* LightEnable;
    void* GetLightEnable;
    void* SetClipPlane;
    void* GetClipPlane;
    void* SetRenderState;
    void* GetRenderState;
    void* BeginStateBlock;
    void* EndStateBlock;
    void* ApplyStateBlock;
    void* CaptureStateBlock;
    void* DeleteStateBlock;
    void* CreateStateBlock;
    void* SetClipStatus;
    void* GetClipStatus;
    void* GetTexture;
    void* SetTexture;
    void* GetTextureStageState;
    void* SetTextureStageState;
    void* ValidateDevice;
    void* GetInfo;
    void* SetPaletteEntries;
    void* GetPaletteEntries;
    void* SetCurrentTexturePalette;
    void* GetCurrentTexturePalette;
    void* DrawPrimitive;
    void* DrawIndexedPrimitive;
    void* DrawPrimitiveUP;
    void* DrawIndexedPrimitiveUP;
    void* ProcessVertices;
    void* CreateVertexShader;
    void* SetVertexShader;
    void* GetVertexShader;
    void* DeleteVertexShader;
    void* SetVertexShaderConstant;
    void* GetVertexShaderConstant;
    void* GetVertexShaderDeclaration;
    void* GetVertexShaderFunction;
    void* SetStreamSource;
    void* GetStreamSource;
    void* SetIndices;
    void* GetIndices;
    void* CreatePixelShader;
    void* SetPixelShader;
    void* GetPixelShader;
    void* DeletePixelShader;
    void* SetPixelShaderConstant;
    void* GetPixelShaderConstant;
    void* GetPixelShaderFunction;
    void* DrawRectPatch;
    void* DrawTriPatch;
    void* DeletePatch;
};

struct IDirect3DResource8Vtbl {
    struct IUnknownVtbl super;
    void* GetDevice;
    void* SetPrivateData;
    void* GetPrivateData;
    void* FreePrivateData;
    void* SetPriority;
    void* GetPriority;
    void* PreLoad;
    void* GetType;
};

struct IDirect3DBaseTexture8Vtbl {
    struct IDirect3DResource8Vtbl super;
    void* SetLOD;
    void* GetLOD;
    void* GetLevelCount;
};

struct IDirect3DTexture8Vtbl {
    struct IDirect3DBaseTexture8Vtbl super;
    void* GetLevelDesc;
    void* GetSurfaceLevel;
    void* LockRect;
    void* UnlockRect;
    void* AddDirtyRect;
};

struct IDirect3DSurface8Vtbl {
    struct IDirect3DResource8Vtbl super;
    void* GetContainer;
    void* GetDesc;
    void* LockRect;
    void* UnlockRect;
};

struct IDirect3DVertexBuffer8Vtbl {
    struct IDirect3DResource8Vtbl super;
    void* Lock;
    void* Unlock;
    void* GetDesc;
};

struct IDirect3D8 {
    struct IDirect3D8Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DDevice8 {
    struct IDirect3DDevice8Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DResource8 {
    struct IDirect3DResource8Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DBaseTexture8 {
    struct IDirect3DBaseTexture8Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DTexture8 {
    struct IDirect3DTexture8Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DSurface8 {
    struct IDirect3DSurface8Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DVertexBuffer8 {
    struct IDirect3DVertexBuffer8Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct D3DPRESENT_PARAMETERS
{
    uint32_t BackBufferWidth;
    uint32_t BackBufferHeight;
    uint32_t BackBufferFormat;
    uint32_t BackBufferCount;
    uint32_t MultiSampleType;
    uint32_t MultiSampleQuality;
    uint32_t SwapEffect;
    HWND hDeviceWindow;
    int32_t Windowed;
    int32_t EnableAutoDepthStencil;
    uint32_t AutoDepthStencilFormat;
    uint32_t Flags;
    uint32_t FullScreen_RefreshRateInHz;
    uint32_t PresentationInterval;
};

struct BRUSH__;
struct ICON__;
struct CURSOR__;
typedef struct BRUSH__ *HBRUSH;
typedef struct ICON__ *HICON;
typedef struct CURSOR__ *HCURSOR;
typedef struct tagWNDCLASSA {
  UINT      style;
  void*     lpfnWndProc;
  int       cbClsExtra;
  int       cbWndExtra;
  HINSTANCE hInstance;
  HICON     hIcon;
  HCURSOR   hCursor;
  HBRUSH    hbrBackground;
  LPCSTR    lpszMenuName;
  LPCSTR    lpszClassName;
} WNDCLASSA;

typedef struct _D3DCAPS8
{
    DWORD   DeviceType;
    UINT    AdapterOrdinal;
    DWORD   Caps;
    DWORD   Caps2;
    DWORD   Caps3;
    DWORD   PresentationIntervals;
    DWORD   CursorCaps;
    DWORD   DevCaps;
    DWORD   PrimitiveMiscCaps;
    DWORD   RasterCaps;
    DWORD   ZCmpCaps;
    DWORD   SrcBlendCaps;
    DWORD   DestBlendCaps;
    DWORD   AlphaCmpCaps;
    DWORD   ShadeCaps;
    DWORD   TextureCaps;
    DWORD   TextureFilterCaps;
    DWORD   CubeTextureFilterCaps;
    DWORD   VolumeTextureFilterCaps;
    DWORD   TextureAddressCaps;
    DWORD   VolumeTextureAddressCaps;
    DWORD   LineCaps;
    DWORD   MaxTextureWidth, MaxTextureHeight;
    DWORD   MaxVolumeExtent;
    DWORD   MaxTextureRepeat;
    DWORD   MaxTextureAspectRatio;
    DWORD   MaxAnisotropy;
    float   MaxVertexW;
    float   GuardBandLeft;
    float   GuardBandTop;
    float   GuardBandRight;
    float   GuardBandBottom;
    float   ExtentsAdjust;
    DWORD   StencilCaps;
    DWORD   FVFCaps;
    DWORD   TextureOpCaps;
    DWORD   MaxTextureBlendStages;
    DWORD   MaxSimultaneousTextures;
    DWORD   VertexProcessingCaps;
    DWORD   MaxActiveLights;
    DWORD   MaxUserClipPlanes;
    DWORD   MaxVertexBlendMatrices;
    DWORD   MaxVertexBlendMatrixIndex;
    float   MaxPointSize;
    DWORD   MaxPrimitiveCount;
    DWORD   MaxVertexIndex;
    DWORD   MaxStreams;
    DWORD   MaxStreamStride;
    DWORD   VertexShaderVersion;
    DWORD   MaxVertexShaderConst;
    DWORD   PixelShaderVersion;
    float   MaxPixelShaderValue;
} D3DCAPS8;

typedef struct _D3DVIEWPORT8 {
  DWORD X;
  DWORD Y;
  DWORD Width;
  DWORD Height;
  float MinZ;
  float MaxZ;
} D3DVIEWPORT8;

//===============================================================
//===============================================================
//===============================================================
//===============================================================

struct DSBUFFERDESC {
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwBufferBytes;
    DWORD dwReserved;
    void* lpwfxFormat;
    GUID guid3DAlgorithm;
};

struct DSBCAPS
{
    uint32_t dwSize;
    uint32_t dwFlags;
    uint32_t dwBufferBytes;
    uint32_t dwUnlockTransferRate;
    uint32_t dwPlayCpuOverhead;
};

struct DSCAPS
{
    uint32_t dwSize;
    uint32_t dwFlags;
    uint32_t dwMinSecondarySampleRate;
    uint32_t dwMaxSecondarySampleRate;
    uint32_t dwPrimaryBuffers;
    uint32_t dwMaxHwMixingAllBuffers;
    uint32_t dwMaxHwMixingStaticBuffers;
    uint32_t dwMaxHwMixingStreamingBuffers;
    uint32_t dwFreeHwMixingAllBuffers;
    uint32_t dwFreeHwMixingStaticBuffers;
    uint32_t dwFreeHwMixingStreamingBuffers;
    uint32_t dwMaxHw3DAllBuffers;
    uint32_t dwMaxHw3DStaticBuffers;
    uint32_t dwMaxHw3DStreamingBuffers;
    uint32_t dwFreeHw3DAllBuffers;
    uint32_t dwFreeHw3DStaticBuffers;
    uint32_t dwFreeHw3DStreamingBuffers;
    uint32_t dwTotalHwMemBytes;
    uint32_t dwFreeHwMemBytes;
    uint32_t dwMaxContigFreeHwMemBytes;
    uint32_t dwUnlockTransferRateHwBuffers;
    uint32_t dwPlayCpuOverheadSwBuffers;
    uint32_t dwReserved1;
    uint32_t dwReserved2;
};

struct WAVEFORMATEX
{
    uint16_t wFormatTag;
    uint16_t nChannels;
    uint32_t nSamplesPerSec;
    uint32_t nAvgBytesPerSec;
    uint16_t nBlockAlign;
    uint16_t wBitsPerSample;
    uint16_t cbSize;
};

struct IUnknown;
struct IDirectSound;
struct IDirectSoundBuffer;

struct IDirectSoundBufferVtbl
{
    struct IUnknownVtbl super;
    int32_t (* GetCaps)(struct IDirectSoundBuffer*, struct DSBCAPS*);
    int32_t (* GetCurrentPosition)(struct IDirectSoundBuffer*, uint32_t*, uint32_t*);
    int32_t (* GetFormat)(struct IDirectSoundBuffer*, WAVEFORMATEX*, uint32_t, uint32_t*);
    int32_t (* GetVolume)(struct IDirectSoundBuffer*, int32_t*);
    int32_t (* GetPan)(struct IDirectSoundBuffer*, int32_t*);
    int32_t (* GetFrequency)(struct IDirectSoundBuffer*, uint32_t*);
    int32_t (* GetStatus)(struct IDirectSoundBuffer*, uint32_t*);
    int32_t (* Initialize)(struct IDirectSoundBuffer*, struct IDirectSound*, struct DSBUFFERDESC*);
    int32_t (* Lock)(struct IDirectSoundBuffer*, uint32_t, uint32_t, void**, uint32_t*, void**, uint32_t*, uint32_t);
    int32_t (* Play)(struct IDirectSoundBuffer*, uint32_t, uint32_t, uint32_t);
    int32_t (* SetCurrentPosition)(struct IDirectSoundBuffer*, uint32_t);
    int32_t (* SetFormat)(struct IDirectSoundBuffer*, struct WAVEFORMATEX*);
    int32_t (* SetVolume)(struct IDirectSoundBuffer*, int32_t);
    int32_t (* SetPan)(struct IDirectSoundBuffer*, int32_t);
    int32_t (* SetFrequency)(struct IDirectSoundBuffer*, uint32_t);
    int32_t (* Stop)(struct IDirectSoundBuffer*);
    int32_t (* Unlock)(struct IDirectSoundBuffer*, void*, uint32_t, void*, uint32_t);
    int32_t (* Restore)(struct IDirectSoundBuffer*);
};

struct IDirectSoundVtbl
{
    struct IUnknownVtbl super;
    int32_t (* CreateSoundBuffer)(struct IDirectSound*, struct DSBUFFERDESC*, struct IDirectSoundBuffer**, struct IUnknown*);
    int32_t (* GetCaps)(struct IDirectSound*, struct DSCAPS*);
    int32_t (* DuplicateSoundBuffer)(struct IDirectSound*, struct IDirectSoundBuffer*, struct IDirectSoundBuffer**);
    int32_t (* SetCooperativeLevel)(struct IDirectSound*, HWND, uint32_t);
    int32_t (* Compact)(struct IDirectSound*);
    int32_t (* GetSpeakerConfig)(struct IDirectSound*, uint32_t*);
    int32_t (* SetSpeakerConfig)(struct IDirectSound*, uint32_t);
    int32_t (* Initialize)(struct IDirectSound*, GUID*);
};

struct IUnknown
{
    struct IUnknownVtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirectSound
{
    struct IDirectSoundVtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirectSoundBuffer
{
    struct IDirectSoundBufferVtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

// ------------------------
// interfaces only accessible through QueryInterface

typedef struct {
  DWORD dwOffset;
  HANDLE hEventNotify;
} DSBPOSITIONNOTIFY;

struct IDirectSoundNotify;
struct IDirectSoundNotifyVtbl {
    struct IUnknownVtbl super;
    int32_t (*SetNotificationPositions)(IDirectSoundNotify*, DWORD, const DSBPOSITIONNOTIFY*); 
};

struct IDirectSoundNotify {
    struct IDirectSoundNotifyVtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct HTASK__;
struct HMMIO__;
typedef struct HTASK__* HTASK;
typedef struct HMMIO__* HMMIO;

struct MMIOINFO {
  DWORD      dwFlags;
  char       fccIOProc[4];
  LRESULT    (*pIOProc)(LPSTR lpmmioinfo, UINT uMsg, LPARAM lParam1, LPARAM lParam2);
  UINT       wErrorRet;
  HTASK      hTask;
  LONG       cchBuffer;
  uint8_t*   pchBuffer;
  uint8_t*   pchNext;
  uint8_t*   pchEndRead;
  uint8_t*   pchEndWrite;
  LONG       lBufOffset;
  LONG       lDiskOffset;
  DWORD      adwInfo[4];
  DWORD      dwReserved1;
  DWORD      dwReserved2;
  HMMIO      hmmio;
};

struct MMCKINFO {
  char   ckid[4];
  DWORD  cksize;
  char   fccType[4];
  DWORD  dwDataOffset;
  DWORD  dwFlags;
};

struct CWaveFile { // DirectX crap
    WAVEFORMATEX* m_pwfx;
    HMMIO         m_hmmio;
    MMCKINFO      m_ck;
    MMCKINFO      m_ckRiff;
    DWORD         m_dwSize;
    MMIOINFO      m_mmioinfoOut;
    DWORD         m_dwFlags;
    BOOL          m_bIsReadingFromMemory;
    BYTE*         m_pbData;
    BYTE*         m_pbDataCur;
    ULONG         m_ulDataSize;
    CHAR*         m_pResourceBuffer;
}

struct CSound {
    IDirectSoundBuffer*  m_apDSBuffer;
    DWORD                m_dwDSBufferSize;
    CWaveFile*           m_pWaveFile;
    DWORD                m_dwNumBuffers;
    DWORD                m_dwCreationFlags;
}

struct CSoundManager {
    IDirectSound* m_pDS;
}
