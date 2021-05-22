// This garbage can be pasted into the "C syntax structs" window of binja
// to add a bunch of Direct3D and DirectInput stuff.

struct HMONITOR__;
struct HDC__;
typedef struct HMONITOR__ * HMONITOR;
typedef struct HDC__ * HDC;

// forward declarations
struct IDirect3D9;
struct IDirect3DBaseTexture9;
struct IDirect3DCubeTexture9;
struct IDirect3DDevice9;
struct IDirect3DIndexBuffer9;
struct IDirect3DPixelShader9;
struct IDirect3DQuery9;
struct IDirect3DResource9;
struct IDirect3DStateBlock9;
struct IDirect3DSurface9;
struct IDirect3DSwapChain9;
struct IDirect3DTexture9;
struct IDirect3DVertexBuffer9;
struct IDirect3DVertexDeclaration9;
struct IDirect3DVertexShader9;
struct IDirect3DVolume9;
struct IDirect3DVolumeTexture9;
struct IUnknown;

struct D3DPSHADERCAPS2_0
{
    uint32_t Caps;
    int32_t DynamicFlowControlDepth;
    int32_t NumTemps;
    int32_t StaticFlowControlDepth;
    int32_t NumInstructionSlots;
};

struct D3DVSHADERCAPS2_0
{
    uint32_t Caps;
    int32_t DynamicFlowControlDepth;
    int32_t NumTemps;
    int32_t StaticFlowControlDepth;
};

struct D3DCAPS9
{
    uint32_t DeviceType;
    uint32_t AdapterOrdinal;
    uint32_t Caps;
    uint32_t Caps2;
    uint32_t Caps3;
    uint32_t PresentationIntervals;
    uint32_t CursorCaps;
    uint32_t DevCaps;
    uint32_t PrimitiveMiscCaps;
    uint32_t RasterCaps;
    uint32_t ZCmpCaps;
    uint32_t SrcBlendCaps;
    uint32_t DestBlendCaps;
    uint32_t AlphaCmpCaps;
    uint32_t ShadeCaps;
    uint32_t TextureCaps;
    uint32_t TextureFilterCaps;
    uint32_t CubeTextureFilterCaps;
    uint32_t VolumeTextureFilterCaps;
    uint32_t TextureAddressCaps;
    uint32_t VolumeTextureAddressCaps;
    uint32_t LineCaps;
    uint32_t MaxTextureWidth;
    uint32_t MaxTextureHeight;
    uint32_t MaxVolumeExtent;
    uint32_t MaxTextureRepeat;
    uint32_t MaxTextureAspectRatio;
    uint32_t MaxAnisotropy;
    float MaxVertexW;
    float GuardBandLeft;
    float GuardBandTop;
    float GuardBandRight;
    float GuardBandBottom;
    float ExtentsAdjust;
    uint32_t StencilCaps;
    uint32_t FVFCaps;
    uint32_t TextureOpCaps;
    uint32_t MaxTextureBlendStages;
    uint32_t MaxSimultaneousTextures;
    uint32_t VertexProcessingCaps;
    uint32_t MaxActiveLights;
    uint32_t MaxUserClipPlanes;
    uint32_t MaxVertexBlendMatrices;
    uint32_t MaxVertexBlendMatrixIndex;
    float MaxPointSize;
    uint32_t MaxPrimitiveCount;
    uint32_t MaxVertexIndex;
    uint32_t MaxStreams;
    uint32_t MaxStreamStride;
    uint32_t VertexShaderVersion;
    uint32_t MaxVertexShaderConst;
    uint32_t PixelShaderVersion;
    float PixelShader1xMaxValue;
    uint32_t DevCaps2;
    float MaxNpatchTessellationLevel;
    uint32_t Reserved5;
    uint32_t MasterAdapterOrdinal;
    uint32_t AdapterOrdinalInGroup;
    uint32_t NumberOfAdaptersInGroup;
    uint32_t DeclTypes;
    uint32_t NumSimultaneousRTs;
    uint32_t StretchRectFilterCaps;
    struct D3DVSHADERCAPS2_0 VS20Caps;
    struct D3DPSHADERCAPS2_0 PS20Caps;
    uint32_t VertexTextureFilterCaps;
    uint32_t MaxVShaderInstructionsExecuted;
    uint32_t MaxPShaderInstructionsExecuted;
    uint32_t MaxVertexShader30InstructionSlots;
    uint32_t MaxPixelShader30InstructionSlots;
};

struct D3DADAPTER_IDENTIFIER9
{
    char Driver[512];
    char Description[512];
    char DeviceName[32];
    struct LARGE_INTEGER DriverVersion;
    uint32_t VendorId;
    uint32_t DeviceId;
    uint32_t SubSysId;
    uint32_t Revision;
    GUID DeviceIdentifier;
    uint32_t WHQLLevel;
};

struct D3DBOX
{
    uint32_t Left;
    uint32_t Top;
    uint32_t Right;
    uint32_t Bottom;
    uint32_t Front;
    uint32_t Back;
};

struct D3DCLIPSTATUS9
{
    uint32_t ClipUnion;
    uint32_t ClipIntersection;
};

struct D3DCOLORVALUE
{
    float r;
    float g;
    float b;
    float a;
};

struct D3DDEVICE_CREATION_PARAMETERS
{
    uint32_t AdapterOrdinal;
    uint32_t DeviceType;
    HWND hFocusWindow;
    uint32_t BehaviorFlags;
};

struct D3DDISPLAYMODE
{
    uint32_t Width;
    uint32_t Height;
    uint32_t RefreshRate;
    uint32_t Format;
};

struct D3DGAMMARAMP
{
    uint16_t red[256];
    uint16_t green[256];
    uint16_t blue[256];
};

struct D3DINDEXBUFFER_DESC
{
    uint32_t Format;
    uint32_t Type;
    uint32_t Usage;
    uint32_t Pool;
    uint32_t Size;
};

struct D3DLOCKED_BOX
{
    int32_t RowPitch;
    int32_t SlicePitch;
    void* pBits;
};

struct D3DLOCKED_RECT
{
    int32_t Pitch;
    void* pBits;
};

struct D3DMATRIX __packed
{
    float m00;
    float m01;
    float m02;
    float m03;
    float m10;
    float m11;
    float m12;
    float m13;
    float m20;
    float m21;
    float m22;
    float m23;
    float m30;
    float m31;
    float m32;
    float m33;
};

struct D3DMATERIAL9
{
    struct D3DCOLORVALUE Diffuse;
    struct D3DCOLORVALUE Ambient;
    struct D3DCOLORVALUE Specular;
    struct D3DCOLORVALUE Emissive;
    float Power;
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

struct D3DRASTER_STATUS
{
    int32_t InVBlank;
    uint32_t ScanLine;
};

struct D3DRECT
{
    int32_t x1;
    int32_t y1;
    int32_t x2;
    int32_t y2;
};

struct D3DRECTPATCH_INFO
{
    uint32_t StartVertexOffsetWidth;
    uint32_t StartVertexOffsetHeight;
    uint32_t Width;
    uint32_t Height;
    uint32_t Stride;
    uint32_t Basis;
    uint32_t Degree;
};

struct D3DSURFACE_DESC
{
    uint32_t Format;
    uint32_t Type;
    uint32_t Usage;
    uint32_t Pool;
    uint32_t MultiSampleType;
    uint32_t MultiSampleQuality;
    uint32_t Width;
    uint32_t Height;
};

struct D3DTRIPATCH_INFO
{
    uint32_t StartVertexOffset;
    uint32_t NumVertices;
    uint32_t Basis;
    uint32_t Degree;
};

struct D3DVECTOR
{
    float x;
    float y;
    float z;
};

struct D3DVERTEXBUFFER_DESC
{
    uint32_t Format;
    uint32_t Type;
    uint32_t Usage;
    uint32_t Pool;
    uint32_t Size;
    uint32_t FVF;
};

struct D3DVERTEXELEMENT9
{
    uint16_t Stream;
    uint16_t Offset;
    char Type;
    char Method;
    char Usage;
    char UsageIndex;
};

struct D3DVIEWPORT9
{
    uint32_t X;
    uint32_t Y;
    uint32_t Width;
    uint32_t Height;
    float MinZ;
    float MaxZ;
};

struct D3DVOLUME_DESC
{
    uint32_t Format;
    uint32_t Type;
    uint32_t Usage;
    uint32_t Pool;
    uint32_t Width;
    uint32_t Height;
    uint32_t Depth;
};

struct D3DLIGHT9
{
    uint32_t Type;
    struct D3DCOLORVALUE Diffuse;
    struct D3DCOLORVALUE Specular;
    struct D3DCOLORVALUE Ambient;
    struct D3DVECTOR Position;
    struct D3DVECTOR Direction;
    float Range;
    float Falloff;
    float Attenuation0;
    float Attenuation1;
    float Attenuation2;
    float Theta;
    float Phi;
};

struct PALETTEENTRY
{
    char peRed;
    char peGreen;
    char peBlue;
    char peFlags;
};

struct HINSTANCERGNDATAHEADER
{
    uint32_t dwSize;
    uint32_t iType;
    uint32_t nCount;
    uint32_t nRgnSize;
    RECT rcBound;
};

struct HINSTANCERGNDATA
{
    struct HINSTANCERGNDATAHEADER rdh;
    char Buffer[1];
};

struct IUnknownVtbl
{
    int32_t (* QueryInterface)(struct IUnknown*, GUID*, void**);
    uint32_t (* AddRef)(struct IUnknown*);
    uint32_t (* Release)(struct IUnknown*);
};

struct IDirect3DResource9Vtbl
{
    struct IUnknownVtbl super;
    int32_t (* GetDevice)(struct IDirect3DResource9*, struct IDirect3DDevice9**);
    int32_t (* SetPrivateData)(struct IDirect3DResource9*, GUID*, void*, uint32_t, uint32_t);
    int32_t (* GetPrivateData)(struct IDirect3DResource9*, GUID*, void*, uint32_t*);
    int32_t (* FreePrivateData)(struct IDirect3DResource9*, GUID*);
    uint32_t (* SetPriority)(struct IDirect3DResource9*, uint32_t);
    uint32_t (* GetPriority)(struct IDirect3DResource9*);
    void (* PreLoad)(struct IDirect3DResource9*);
    uint32_t (* GetType)(struct IDirect3DResource9*);
};

struct IDirect3D9Vtbl
{
    struct IUnknownVtbl super;
    int32_t (* RegisterSoftwareDevice)(struct IDirect3D9*, void*);
    uint32_t (* GetAdapterCount)(struct IDirect3D9*);
    int32_t (* GetAdapterIdentifier)(struct IDirect3D9*, uint32_t, uint32_t, struct D3DADAPTER_IDENTIFIER9*);
    uint32_t (* GetAdapterModeCount)(struct IDirect3D9*, uint32_t, uint32_t);
    int32_t (* EnumAdapterModes)(struct IDirect3D9*, uint32_t, uint32_t, uint32_t, struct D3DDISPLAYMODE*);
    int32_t (* GetAdapterDisplayMode)(struct IDirect3D9*, uint32_t, struct D3DDISPLAYMODE*);
    int32_t (* CheckDeviceType)(struct IDirect3D9*, uint32_t, uint32_t, uint32_t, uint32_t, int32_t);
    int32_t (* CheckDeviceFormat)(struct IDirect3D9*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    int32_t (* CheckDeviceMultiSampleType)(struct IDirect3D9*, uint32_t, uint32_t, uint32_t, int32_t, uint32_t, uint32_t*);
    int32_t (* CheckDepthStencilMatch)(struct IDirect3D9*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    int32_t (* CheckDeviceFormatConversion)(struct IDirect3D9*, uint32_t, uint32_t, uint32_t, uint32_t);
    int32_t (* GetDeviceCaps)(struct IDirect3D9*, uint32_t, uint32_t, struct D3DCAPS9*);
    HMONITOR* (* GetAdapterMonitor)(struct IDirect3D9*, uint32_t);
    int32_t (* CreateDevice)(struct IDirect3D9*, uint32_t, uint32_t, HWND, uint32_t, struct D3DPRESENT_PARAMETERS*, struct IDirect3DDevice9**);
};

struct IDirect3DBaseTexture9Vtbl
{
    struct IDirect3DResource9Vtbl super;
    uint32_t (* SetLOD)(struct IDirect3DBaseTexture9*, uint32_t);
    uint32_t (* GetLOD)(struct IDirect3DBaseTexture9*);
    uint32_t (* GetLevelCount)(struct IDirect3DBaseTexture9*);
    int32_t (* SetAutoGenFilterType)(struct IDirect3DBaseTexture9*, uint32_t);
    uint32_t (* GetAutoGenFilterType)(struct IDirect3DBaseTexture9*);
    void (* GenerateMipSubLevels)(struct IDirect3DBaseTexture9*);
};

struct IDirect3DCubeTexture9Vtbl
{
    struct IDirect3DBaseTexture9Vtbl super;
    int32_t (* GetLevelDesc)(struct IDirect3DCubeTexture9*, uint32_t, struct D3DSURFACE_DESC*);
    int32_t (* GetCubeMapSurface)(struct IDirect3DCubeTexture9*, uint32_t, uint32_t, struct IDirect3DSurface9**);
    int32_t (* LockRect)(struct IDirect3DCubeTexture9*, uint32_t, uint32_t, struct D3DLOCKED_RECT*, RECT*, uint32_t);
    int32_t (* UnlockRect)(struct IDirect3DCubeTexture9*, uint32_t, uint32_t);
    int32_t (* AddDirtyRect)(struct IDirect3DCubeTexture9*, uint32_t, RECT*);
};

struct IDirect3DDevice9Vtbl
{
    struct IUnknownVtbl super;
    int32_t (* TestCooperativeLevel)(struct IDirect3DDevice9*);
    uint32_t (* GetAvailableTextureMem)(struct IDirect3DDevice9*);
    int32_t (* EvictManagedResources)(struct IDirect3DDevice9*);
    int32_t (* GetDirect3D)(struct IDirect3DDevice9*, struct IDirect3D9**);
    int32_t (* GetDeviceCaps)(struct IDirect3DDevice9*, struct D3DCAPS9*);
    int32_t (* GetDisplayMode)(struct IDirect3DDevice9*, uint32_t, struct D3DDISPLAYMODE*);
    int32_t (* GetCreationParameters)(struct IDirect3DDevice9*, struct D3DDEVICE_CREATION_PARAMETERS*);
    int32_t (* SetCursorProperties)(struct IDirect3DDevice9*, uint32_t, uint32_t, struct IDirect3DSurface9*);
    void (* SetCursorPosition)(struct IDirect3DDevice9*, int32_t, int32_t, uint32_t);
    int32_t (* ShowCursor)(struct IDirect3DDevice9*, int32_t);
    int32_t (* CreateAdditionalSwapChain)(struct IDirect3DDevice9*, struct D3DPRESENT_PARAMETERS*, struct IDirect3DSwapChain9**);
    int32_t (* GetSwapChain)(struct IDirect3DDevice9*, uint32_t, struct IDirect3DSwapChain9**);
    uint32_t (* GetNumberOfSwapChains)(struct IDirect3DDevice9*);
    int32_t (* Reset)(struct IDirect3DDevice9*, struct D3DPRESENT_PARAMETERS*);
    int32_t (* Present)(struct IDirect3DDevice9*, RECT*, RECT*, HWND, struct HINSTANCERGNDATA*);
    int32_t (* GetBackBuffer)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t, struct IDirect3DSurface9**);
    int32_t (* GetRasterStatus)(struct IDirect3DDevice9*, uint32_t, struct D3DRASTER_STATUS*);
    int32_t (* SetDialogBoxMode)(struct IDirect3DDevice9*, int32_t);
    void (* SetGammaRamp)(struct IDirect3DDevice9*, uint32_t, uint32_t, struct D3DGAMMARAMP*);
    void (* GetGammaRamp)(struct IDirect3DDevice9*, uint32_t, struct D3DGAMMARAMP*);
    int32_t (* CreateTexture)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, struct IDirect3DTexture9**, void**);
    int32_t (* CreateVolumeTexture)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, struct IDirect3DVolumeTexture9**, void**);
    int32_t (* CreateCubeTexture)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, struct IDirect3DCubeTexture9**, void**);
    int32_t (* CreateVertexBuffer)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t, uint32_t, struct IDirect3DVertexBuffer9**, void**);
    int32_t (* CreateIndexBuffer)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t, uint32_t, struct IDirect3DIndexBuffer9**, void**);
    int32_t (* CreateRenderTarget)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, int32_t, struct IDirect3DSurface9**, void**);
    int32_t (* CreateDepthStencilSurface)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, int32_t, struct IDirect3DSurface9**, void**);
    int32_t (* UpdateSurface)(struct IDirect3DDevice9*, struct IDirect3DSurface9*, RECT*, struct IDirect3DSurface9*, POINT*);
    int32_t (* UpdateTexture)(struct IDirect3DDevice9*, struct IDirect3DBaseTexture9*, struct IDirect3DBaseTexture9*);
    int32_t (* GetRenderTargetData)(struct IDirect3DDevice9*, struct IDirect3DSurface9*, struct IDirect3DSurface9*);
    int32_t (* GetFrontBufferData)(struct IDirect3DDevice9*, uint32_t, struct IDirect3DSurface9*);
    int32_t (* StretchRect)(struct IDirect3DDevice9*, struct IDirect3DSurface9*, RECT*, struct IDirect3DSurface9*, RECT*, uint32_t);
    int32_t (* ColorFill)(struct IDirect3DDevice9*, struct IDirect3DSurface9*, RECT*, uint32_t);
    int32_t (* CreateOffscreenPlainSurface)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t, uint32_t, struct IDirect3DSurface9**, void**);
    int32_t (* SetRenderTarget)(struct IDirect3DDevice9*, uint32_t, struct IDirect3DSurface9*);
    int32_t (* GetRenderTarget)(struct IDirect3DDevice9*, uint32_t, struct IDirect3DSurface9**);
    int32_t (* SetDepthStencilSurface)(struct IDirect3DDevice9*, struct IDirect3DSurface9*);
    int32_t (* GetDepthStencilSurface)(struct IDirect3DDevice9*, struct IDirect3DSurface9**);
    int32_t (* BeginScene)(struct IDirect3DDevice9*);
    int32_t (* EndScene)(struct IDirect3DDevice9*);
    int32_t (* Clear)(struct IDirect3DDevice9*, uint32_t, struct D3DRECT*, uint32_t, uint32_t, float, uint32_t);
    int32_t (* SetTransform)(struct IDirect3DDevice9*, uint32_t, struct D3DMATRIX*);
    int32_t (* GetTransform)(struct IDirect3DDevice9*, uint32_t, struct D3DMATRIX*);
    int32_t (* MultiplyTransform)(struct IDirect3DDevice9*, uint32_t, struct D3DMATRIX*);
    int32_t (* SetViewport)(struct IDirect3DDevice9*, struct D3DVIEWPORT9*);
    int32_t (* GetViewport)(struct IDirect3DDevice9*, struct D3DVIEWPORT9*);
    int32_t (* SetMaterial)(struct IDirect3DDevice9*, struct D3DMATERIAL9*);
    int32_t (* GetMaterial)(struct IDirect3DDevice9*, struct D3DMATERIAL9*);
    int32_t (* SetLight)(struct IDirect3DDevice9*, uint32_t, struct D3DLIGHT9*);
    int32_t (* GetLight)(struct IDirect3DDevice9*, uint32_t, struct D3DLIGHT9*);
    int32_t (* LightEnable)(struct IDirect3DDevice9*, uint32_t, int32_t);
    int32_t (* GetLightEnable)(struct IDirect3DDevice9*, uint32_t, int32_t*);
    int32_t (* SetClipPlane)(struct IDirect3DDevice9*, uint32_t, float*);
    int32_t (* GetClipPlane)(struct IDirect3DDevice9*, uint32_t, float*);
    int32_t (* SetRenderState)(struct IDirect3DDevice9*, uint32_t, uint32_t);
    int32_t (* GetRenderState)(struct IDirect3DDevice9*, uint32_t, uint32_t*);
    int32_t (* CreateStateBlock)(struct IDirect3DDevice9*, uint32_t, struct IDirect3DStateBlock9**);
    int32_t (* BeginStateBlock)(struct IDirect3DDevice9*);
    int32_t (* EndStateBlock)(struct IDirect3DDevice9*, struct IDirect3DStateBlock9**);
    int32_t (* SetClipStatus)(struct IDirect3DDevice9*, struct D3DCLIPSTATUS9*);
    int32_t (* GetClipStatus)(struct IDirect3DDevice9*, struct D3DCLIPSTATUS9*);
    int32_t (* GetTexture)(struct IDirect3DDevice9*, uint32_t, struct IDirect3DBaseTexture9**);
    int32_t (* SetTexture)(struct IDirect3DDevice9*, uint32_t, struct IDirect3DBaseTexture9*);
    int32_t (* GetTextureStageState)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t*);
    int32_t (* SetTextureStageState)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t);
    int32_t (* GetSamplerState)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t*);
    int32_t (* SetSamplerState)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t);
    int32_t (* ValidateDevice)(struct IDirect3DDevice9*, uint32_t*);
    int32_t (* SetPaletteEntries)(struct IDirect3DDevice9*, uint32_t, struct PALETTEENTRY*);
    int32_t (* GetPaletteEntries)(struct IDirect3DDevice9*, uint32_t, struct PALETTEENTRY*);
    int32_t (* SetCurrentTexturePalette)(struct IDirect3DDevice9*, uint32_t);
    int32_t (* GetCurrentTexturePalette)(struct IDirect3DDevice9*, uint32_t*);
    int32_t (* SetScissorRect)(struct IDirect3DDevice9*, RECT*);
    int32_t (* GetScissorRect)(struct IDirect3DDevice9*, RECT*);
    int32_t (* SetSoftwareVertexProcessing)(struct IDirect3DDevice9*, int32_t);
    int32_t (* GetSoftwareVertexProcessing)(struct IDirect3DDevice9*);
    int32_t (* SetNPatchMode)(struct IDirect3DDevice9*, float);
    float (* GetNPatchMode)(struct IDirect3DDevice9*);
    int32_t (* DrawPrimitive)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t);
    int32_t (* DrawIndexedPrimitive)(struct IDirect3DDevice9*, uint32_t, int32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    int32_t (* DrawPrimitiveUP)(struct IDirect3DDevice9*, uint32_t, uint32_t, void*, uint32_t);
    int32_t (* DrawIndexedPrimitiveUP)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t, uint32_t, void*, uint32_t, void*, uint32_t);
    int32_t (* ProcessVertices)(struct IDirect3DDevice9*, uint32_t, uint32_t, uint32_t, struct IDirect3DVertexBuffer9*, struct IDirect3DVertexDeclaration9*, uint32_t);
    int32_t (* CreateVertexDeclaration)(struct IDirect3DDevice9*, struct D3DVERTEXELEMENT9*, struct IDirect3DVertexDeclaration9**);
    int32_t (* SetVertexDeclaration)(struct IDirect3DDevice9*, struct IDirect3DVertexDeclaration9*);
    int32_t (* GetVertexDeclaration)(struct IDirect3DDevice9*, struct IDirect3DVertexDeclaration9**);
    int32_t (* SetFVF)(struct IDirect3DDevice9*, uint32_t);
    int32_t (* GetFVF)(struct IDirect3DDevice9*, uint32_t*);
    int32_t (* CreateVertexShader)(struct IDirect3DDevice9*, uint32_t*, struct IDirect3DVertexShader9**);
    int32_t (* SetVertexShader)(struct IDirect3DDevice9*, struct IDirect3DVertexShader9*);
    int32_t (* GetVertexShader)(struct IDirect3DDevice9*, struct IDirect3DVertexShader9**);
    int32_t (* SetVertexShaderConstantF)(struct IDirect3DDevice9*, uint32_t, float*, uint32_t);
    int32_t (* GetVertexShaderConstantF)(struct IDirect3DDevice9*, uint32_t, float*, uint32_t);
    int32_t (* SetVertexShaderConstantI)(struct IDirect3DDevice9*, uint32_t, int32_t*, uint32_t);
    int32_t (* GetVertexShaderConstantI)(struct IDirect3DDevice9*, uint32_t, int32_t*, uint32_t);
    int32_t (* SetVertexShaderConstantB)(struct IDirect3DDevice9*, uint32_t, int32_t*, uint32_t);
    int32_t (* GetVertexShaderConstantB)(struct IDirect3DDevice9*, uint32_t, int32_t*, uint32_t);
    int32_t (* SetStreamSource)(struct IDirect3DDevice9*, uint32_t, struct IDirect3DVertexBuffer9*, uint32_t, uint32_t);
    int32_t (* GetStreamSource)(struct IDirect3DDevice9*, uint32_t, struct IDirect3DVertexBuffer9**, uint32_t*, uint32_t*);
    int32_t (* SetStreamSourceFreq)(struct IDirect3DDevice9*, uint32_t, uint32_t);
    int32_t (* GetStreamSourceFreq)(struct IDirect3DDevice9*, uint32_t, uint32_t*);
    int32_t (* SetIndices)(struct IDirect3DDevice9*, struct IDirect3DIndexBuffer9*);
    int32_t (* GetIndices)(struct IDirect3DDevice9*, struct IDirect3DIndexBuffer9**);
    int32_t (* CreatePixelShader)(struct IDirect3DDevice9*, uint32_t*, struct IDirect3DPixelShader9**);
    int32_t (* SetPixelShader)(struct IDirect3DDevice9*, struct IDirect3DPixelShader9*);
    int32_t (* GetPixelShader)(struct IDirect3DDevice9*, struct IDirect3DPixelShader9**);
    int32_t (* SetPixelShaderConstantF)(struct IDirect3DDevice9*, uint32_t, float*, uint32_t);
    int32_t (* GetPixelShaderConstantF)(struct IDirect3DDevice9*, uint32_t, float*, uint32_t);
    int32_t (* SetPixelShaderConstantI)(struct IDirect3DDevice9*, uint32_t, int32_t*, uint32_t);
    int32_t (* GetPixelShaderConstantI)(struct IDirect3DDevice9*, uint32_t, int32_t*, uint32_t);
    int32_t (* SetPixelShaderConstantB)(struct IDirect3DDevice9*, uint32_t, int32_t*, uint32_t);
    int32_t (* GetPixelShaderConstantB)(struct IDirect3DDevice9*, uint32_t, int32_t*, uint32_t);
    int32_t (* DrawRectPatch)(struct IDirect3DDevice9*, uint32_t, float*, struct D3DRECTPATCH_INFO*);
    int32_t (* DrawTriPatch)(struct IDirect3DDevice9*, uint32_t, float*, struct D3DTRIPATCH_INFO*);
    int32_t (* DeletePatch)(struct IDirect3DDevice9*, uint32_t);
    int32_t (* CreateQuery)(struct IDirect3DDevice9*, uint32_t, struct IDirect3DQuery9**);
};

struct IDirect3DIndexBuffer9Vtbl
{
    struct IDirect3DResource9Vtbl super;
    int32_t (* Lock)(struct IDirect3DIndexBuffer9*, uint32_t, uint32_t, void**, uint32_t);
    int32_t (* Unlock)(struct IDirect3DIndexBuffer9*);
    int32_t (* GetDesc)(struct IDirect3DIndexBuffer9*, struct D3DINDEXBUFFER_DESC*);
};

struct IDirect3DPixelShader9Vtbl
{
    struct IUnknownVtbl super;
    int32_t (* GetDevice)(struct IDirect3DPixelShader9*, struct IDirect3DDevice9**);
    int32_t (* GetFunction)(struct IDirect3DPixelShader9*, void*, uint32_t*);
};

struct IDirect3DQuery9Vtbl
{
    struct IUnknownVtbl super;
    int32_t (* GetDevice)(struct IDirect3DQuery9*, struct IDirect3DDevice9**);
    uint32_t (* GetType)(struct IDirect3DQuery9*);
    uint32_t (* GetDataSize)(struct IDirect3DQuery9*);
    int32_t (* Issue)(struct IDirect3DQuery9*, uint32_t);
    int32_t (* GetData)(struct IDirect3DQuery9*, void*, uint32_t, uint32_t);
};

struct IDirect3DStateBlock9Vtbl
{
    struct IUnknownVtbl super;
    int32_t (* GetDevice)(struct IDirect3DStateBlock9*, struct IDirect3DDevice9**);
    int32_t (* Capture)(struct IDirect3DStateBlock9*);
    int32_t (* Apply)(struct IDirect3DStateBlock9*);
};

struct IDirect3DSurface9Vtbl
{
    struct IDirect3DResource9Vtbl super;
    int32_t (* GetContainer)(struct IDirect3DSurface9*, GUID*, void**);
    int32_t (* GetDesc)(struct IDirect3DSurface9*, struct D3DSURFACE_DESC*);
    int32_t (* LockRect)(struct IDirect3DSurface9*, struct D3DLOCKED_RECT*, RECT*, uint32_t);
    int32_t (* UnlockRect)(struct IDirect3DSurface9*);
    int32_t (* GetDC)(struct IDirect3DSurface9*, HDC*);
    int32_t (* ReleaseDC)(struct IDirect3DSurface9*, HDC);
};

struct IDirect3DSwapChain9Vtbl
{
    struct IUnknownVtbl super;
    int32_t (* Present)(struct IDirect3DSwapChain9*, RECT*, RECT*, HWND, struct HINSTANCERGNDATA*, uint32_t);
    int32_t (* GetFrontBufferData)(struct IDirect3DSwapChain9*, struct IDirect3DSurface9*);
    int32_t (* GetBackBuffer)(struct IDirect3DSwapChain9*, uint32_t, uint32_t, struct IDirect3DSurface9**);
    int32_t (* GetRasterStatus)(struct IDirect3DSwapChain9*, struct D3DRASTER_STATUS*);
    int32_t (* GetDisplayMode)(struct IDirect3DSwapChain9*, struct D3DDISPLAYMODE*);
    int32_t (* GetDevice)(struct IDirect3DSwapChain9*, struct IDirect3DDevice9**);
    int32_t (* GetPresentParameters)(struct IDirect3DSwapChain9*, struct D3DPRESENT_PARAMETERS*);
};

struct IDirect3DTexture9Vtbl
{
    struct IDirect3DBaseTexture9Vtbl super;
    int32_t (* GetLevelDesc)(struct IDirect3DTexture9*, uint32_t, struct D3DSURFACE_DESC*);
    int32_t (* GetSurfaceLevel)(struct IDirect3DTexture9*, uint32_t, struct IDirect3DSurface9**);
    int32_t (* LockRect)(struct IDirect3DTexture9*, uint32_t, struct D3DLOCKED_RECT*, RECT*, uint32_t);
    int32_t (* UnlockRect)(struct IDirect3DTexture9*, uint32_t);
    int32_t (* AddDirtyRect)(struct IDirect3DTexture9*, RECT*);
};

struct IDirect3DVertexBuffer9Vtbl
{
    struct IDirect3DResource9Vtbl super;
    int32_t (* Lock)(struct IDirect3DVertexBuffer9*, uint32_t, uint32_t, void**, uint32_t);
    int32_t (* Unlock)(struct IDirect3DVertexBuffer9*);
    int32_t (* GetDesc)(struct IDirect3DVertexBuffer9*, struct D3DVERTEXBUFFER_DESC*);
};

struct IDirect3DVertexDeclaration9Vtbl
{
    struct IUnknownVtbl super;
    int32_t (* GetDevice)(struct IDirect3DVertexDeclaration9*, struct IDirect3DDevice9**);
    int32_t (* GetDeclaration)(struct IDirect3DVertexDeclaration9*, struct D3DVERTEXELEMENT9*, uint32_t*);
};

struct IDirect3DVertexShader9Vtbl
{
    struct IUnknownVtbl super;
    int32_t (* GetDevice)(struct IDirect3DVertexShader9*, struct IDirect3DDevice9**);
    int32_t (* GetFunction)(struct IDirect3DVertexShader9*, void*, uint32_t*);
};

struct IDirect3DVolume9Vtbl
{
    struct IUnknownVtbl super;
    int32_t (* GetDevice)(struct IDirect3DVolume9*, struct IDirect3DDevice9**);
    int32_t (* SetPrivateData)(struct IDirect3DVolume9*, GUID*, void*, uint32_t, uint32_t);
    int32_t (* GetPrivateData)(struct IDirect3DVolume9*, GUID*, void*, uint32_t*);
    int32_t (* FreePrivateData)(struct IDirect3DVolume9*, GUID*);
    int32_t (* GetContainer)(struct IDirect3DVolume9*, GUID*, void**);
    int32_t (* GetDesc)(struct IDirect3DVolume9*, struct D3DVOLUME_DESC*);
    int32_t (* LockBox)(struct IDirect3DVolume9*, struct D3DLOCKED_BOX*, struct D3DBOX*, uint32_t);
    int32_t (* UnlockBox)(struct IDirect3DVolume9*);
};

struct IDirect3DVolumeTexture9Vtbl
{
    struct IDirect3DBaseTexture9Vtbl super;
    int32_t (* GetLevelDesc)(struct IDirect3DVolumeTexture9*, uint32_t, struct D3DVOLUME_DESC*);
    int32_t (* GetVolumeLevel)(struct IDirect3DVolumeTexture9*, uint32_t, struct IDirect3DVolume9**);
    int32_t (* LockBox)(struct IDirect3DVolumeTexture9*, uint32_t, struct D3DLOCKED_BOX*, struct D3DBOX*, uint32_t);
    int32_t (* UnlockBox)(struct IDirect3DVolumeTexture9*, uint32_t);
    int32_t (* AddDirtyBox)(struct IDirect3DVolumeTexture9*, struct D3DBOX*);
};

struct IDirect3D9
{
    struct IDirect3D9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DResource9
{
    struct IDirect3DResource9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DBaseTexture9
{
    struct IDirect3DBaseTexture9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DCubeTexture9
{
    struct IDirect3DCubeTexture9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DDevice9
{
    struct IDirect3DDevice9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DIndexBuffer9
{
    struct IDirect3DIndexBuffer9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DPixelShader9
{
    struct IDirect3DPixelShader9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DQuery9
{
    struct IDirect3DQuery9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DStateBlock9
{
    struct IDirect3DStateBlock9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DSurface9
{
    struct IDirect3DSurface9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DSwapChain9
{
    struct IDirect3DSwapChain9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DTexture9
{
    struct IDirect3DTexture9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DVertexBuffer9
{
    struct IDirect3DVertexBuffer9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DVertexDeclaration9
{
    struct IDirect3DVertexDeclaration9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DVertexShader9
{
    struct IDirect3DVertexShader9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DVolume9
{
    struct IDirect3DVolume9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct IDirect3DVolumeTexture9
{
    struct IDirect3DVolumeTexture9Vtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct BITMAPFILEHEADER __packed {
    char  bfType[2];
    DWORD bfSize;
    WORD  bfReserved1;
    WORD  bfReserved2;
    DWORD bfOffBits;
}

struct RGBQUAD {
    BYTE rgbBlue;
    BYTE rgbGreen;
    BYTE rgbRed;
    BYTE rgbReserved;
}

struct BITMAPINFOHEADER
{
    DWORD biSize;
    LONG biWidth;
    LONG biHeight;
    WORD biPlanes;
    WORD biBitCount;
    DWORD biCompression;
    DWORD biSizeImage;
    LONG biXPelsPerMeter;
    LONG biYPelsPerMeter;
    DWORD biClrUsed;
    DWORD biClrImportant;
};

struct JOYCAPSA __packed {
  WORD  wMid;
  WORD  wPid;
  CHAR  szPname[32];
  UINT  wXmin;
  UINT  wXmax;
  UINT  wYmin;
  UINT  wYmax;
  UINT  wZmin;
  UINT  wZmax;
  UINT  wNumButtons;
  UINT  wPeriodMin;
  UINT  wPeriodMax;
  UINT  wRmin;
  UINT  wRmax;
  UINT  wUmin;
  UINT  wUmax;
  UINT  wVmin;
  UINT  wVmax;
  UINT  wCaps;
  UINT  wMaxAxes;
  UINT  wNumAxes;
  UINT  wMaxButtons;
  CHAR  szRegKey[32];
  CHAR  szOEMVxD[260];
};

struct DIDEVICEOBJECTINSTANCEA {
    DWORD   dwSize;
    GUID    guidType;
    DWORD   dwOfs;
    DWORD   dwType;
    DWORD   dwFlags;
    CHAR    tszName[260];
    DWORD   dwFFMaxForce;
    DWORD   dwFFForceResolution;
    WORD    wCollectionNumber;
    WORD    wDesignatorIndex;
    WORD    wUsagePage;
    WORD    wUsage;
    DWORD   dwDimension;
    WORD    wExponent;
    WORD    wReportId;
};

struct DIDEVICEINSTANCEA {
    DWORD   dwSize;
    GUID    guidInstance;
    GUID    guidProduct;
    DWORD   dwDevType;
    CHAR    tszInstanceName[260];
    CHAR    tszProductName[260];
    GUID    guidFFDriver;
    WORD    wUsagePage;
    WORD    wUsage;
};

// IDirectInputEffect
//    #undef INTERFACE
//    #define INTERFACE IDirectInputEffect

struct IDirectInput8AVtbl {
    struct IUnknownVtbl super;
    void *CreateDevice;
    void *EnumDevices;
    void *GetDeviceStatus;
    void *RunControlPanel;
    void *Initialize;
    void *FindDevice;
    void *EnumDevicesBySemantics;
    void *ConfigureDevices;
};

struct IDirectInput8A {
    struct IDirectInput8AVtbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};



struct IDirectInputDevice8AVTbl {
    struct IUnknownVtbl super;
    void *GetCapabilities;
    void *EnumObjects;
    void *GetProperty;
    void *SetProperty;
    void *Acquire;
    void *Unacquire;
    void *GetDeviceState;
    void *GetDeviceData;
    void *SetDataFormat;
    void *SetEventNotification;
    void *SetCooperativeLevel;
    void *GetObjectInfo;
    void *GetDeviceInfo;
    void *RunControlPanel;
    void *Initialize;
    void *CreateEffect;
    void *EnumEffects;
    void *GetEffectInfo;
    void *GetForceFeedbackState;
    void *SendForceFeedbackCommand;
    void *EnumCreatedEffectObjects;
    void *Escape;
    void *Poll;
    void *SendDeviceData;
    void *EnumEffectsInFile;
    void *WriteEffectToFile;
    void *BuildActionMap;
    void *SetActionMap;
    void *GetImageInfo;
};

struct IDirectInputDevice8A {
    struct IDirectInputDevice8AVTbl* vtable;
    char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
};

struct DIOBJECTDATAFORMAT {
    GUID * pguid;
    DWORD dwOfs;
    DWORD dwType;
    DWORD dwFlags;
};

struct DIDATAFORMAT {
    DWORD dwSize;
    DWORD dwObjSize;
    DWORD dwFlags;
    DWORD dwDataSize;
    DWORD dwNumObjs;
    DIOBJECTDATAFORMAT *rgodf;
};

// struct DIDEVICEINSTANCEA {
//     DWORD dwSize;
//     GUID guidInstance;
//     GUID guidProduct;
//     DWORD dwDevType;
//     char tszInstanceName[260];
//     char tszProductName[260];
//     GUID guidFFDriver;
//     WORD wUsagePage;
//     WORD wUsage;
// }

struct DIDEVCAPS {
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwDevType;
    DWORD dwAxes;
    DWORD dwButtons;
    DWORD dwPOVs;
    DWORD dwFFSamplePeriod;
    DWORD dwFFMinTimeResolution;
    DWORD dwFirmwareRevision;
    DWORD dwHardwareRevision;
    DWORD dwFFDriverVersion;
}

// struct DIDEVICEOBJECTINSTANCEA
// {
//     DWORD dwSize;
//     GUID guidType;
//     DWORD dwOfs;
//     DWORD dwType;
//     DWORD dwFlags;
//     char tszName[260];
//     DWORD dwFFMaxForce;
//     DWORD dwFFForceResolution;
//     WORD wCollectionNumber;
//     WORD wDesignatorIndex;
//     WORD wUsagePage;
//     WORD wUsage;
//     DWORD dwDimension;
//     WORD wExponent;
//     WORD wReportId;
// };

struct TIMECAPS {
  UINT wPeriodMin;
  UINT wPeriodMax;
};
