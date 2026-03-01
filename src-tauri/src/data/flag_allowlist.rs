/// The 17 officially allowed FFlags from Roblox's September 2025 announcement.
pub static ALLOWED_FLAGS: &[&str] = &[
    // Geometry/CSG (4)
    "FIntCSGLevelOfDetailSwitchingDistance",
    "FIntCSGLevelOfDetailSwitchingDistanceL12",
    "FIntCSGLevelOfDetailSwitchingDistanceL23",
    "FIntCSGLevelOfDetailSwitchingDistanceL34",
    // Rendering (9)
    "FIntDebugTextureManagerSkipMips",
    "FIntRenderGrassDetailStrands",
    "FIntRenderGrassHeightScaler",
    "FIntTerrainArraySliceSize",
    "FIntFRMMinGrassDistance",
    "FIntFRMMaxGrassDistance",
    "FStringGrassGPUTextureQuality",
    "FIntMSAASamples",
    "DFIntDebugFRMQualityLevelOverride",
    // UI/Misc (4)
    "FFlagGrassReducedMotion",
    "FFlagDebugGraphicsPreferD3D11",
    "FFlagDebugGraphicsPreferVulkan",
    "FFlagHandleAltEnterFullscreenManually",
];

/// Check if a given flag name is in the official allowlist.
pub fn is_allowed_flag(flag_name: &str) -> bool {
    ALLOWED_FLAGS.iter().any(|&f| f == flag_name)
}
