# JNI: Rust looks these up by name (docs/native-contract.md).
-keep class com.zeronet.mobile.core.ZrayNative { *; }
-keep interface com.zeronet.mobile.core.NativeListener { *; }
-keep class * implements com.zeronet.mobile.core.NativeListener { *; }
-keepclasseswithmembernames class * { native <methods>; }
