use crate::models::ScanVerdict;

/// Critical flags: desync/physics manipulation that give competitive advantage.
pub static CRITICAL_FLAGS: &[&str] = &[
    "DFIntS2PhysicsSenderRate",
    "FFlagSimDefaultPaletteNewFrequency",
    "DFIntAssemblyExtentsExpansionStudHundredth",
    "FFlagDebugSimDefaultPaletteNewFrequency",
    "DFIntReplicatorClusterPacketLimit",
    "DFIntReplicatorWritePacketLimit",
];

/// High severity flags: visual advantages.
pub static HIGH_FLAGS: &[&str] = &[
    "FIntDebugTextureManagerSkipMips",
    "FFlagDebugSkyGray",
    "DFIntCSGLevelOfDetailSwitchingDistance",
    "FFlagGlobalWindRendering",
    "FIntRenderShadowIntensity",
    "DFFlagDebugRenderForceTechnologyVoxel",
    "FFlagFastGPULightCulling3",
    "FFlagDebugDisableDeferredLighting",
    "FIntFullscreenTitleBarTriggerDelayMillis",
    "DFIntAnimationLodFacsDistanceMax",
    "DFIntAnimationLodFacsDistanceMin",
    "DFIntAnimationLodFacsVisibilityDenominator",
    "FIntCameraMaxZoomDistance",
    "DFIntCanHideGuiGroupId",
    "FFlagGuiHidingApiSupport2",
];

/// Medium severity flags: moderate advantages.
pub static MEDIUM_FLAGS: &[&str] = &[
    "DFIntTaskSchedulerTargetFps",
    "FFlagHandleAltEnterFullscreenManually",
    "DFFlagDebugPauseVoxelizer",
    "FFlagAdServiceEnabled",
    "FIntRenderLocalLightUpdatesMax",
    "FIntRenderLocalLightUpdatesMin",
    "FIntRobloxGuiBlurIntensity",
    "DFIntVoiceChatMaxRecordedDataDeliveryIntervalMs",
    "FIntRenderMaxShadowAtlasUsageBeforeDownscale",
    "FFlagRenderTestEnableDistanceCulling",
    "DFFlagDebugSkipMeshVoxelizer",
    "FFlagTaskSchedulerLimitTargetFpsTo2402",
    "FIntTargetRefreshRate",
    "FIntRefreshRateLowerBound",
];

/// Get the severity verdict for a given flag name.
/// Returns Flagged for critical, Suspicious for high/medium, and Clean if not found.
pub fn get_flag_severity(flag_name: &str) -> ScanVerdict {
    if CRITICAL_FLAGS.iter().any(|&f| f == flag_name) {
        return ScanVerdict::Flagged;
    }
    if HIGH_FLAGS.iter().any(|&f| f == flag_name) {
        return ScanVerdict::Suspicious;
    }
    if MEDIUM_FLAGS.iter().any(|&f| f == flag_name) {
        return ScanVerdict::Suspicious;
    }
    ScanVerdict::Clean
}
