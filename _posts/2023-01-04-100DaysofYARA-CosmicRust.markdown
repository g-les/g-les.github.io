---
layout: post
title: "100DaysofYARA - CosmicRust"
date: 2024-01-04
categories: yara
---

# 100DaysofYARA - CosmicRust

Today another quick one for, you guessed it, a TA444 (aka Sapphire Sleet, BLUENOROFF, STARDUST CHOLLIMA) Macho family we call CosmicRust! This one is written in Rust, and feels like a less mature version of RustBucket (check out the blogs on RustBucket by the homies at [JAMF](https://www.jamf.com/blog/bluenoroff-apt-targets-macos-rustbucket-malware/) and [Elastic](https://www.elastic.co/security-labs/DPRK-strikes-using-a-new-variant-of-rustbucket)) - the main difference is CosmicRust uses WebSockets for communications.

CosmicRust, thankfully, used an ad-hoc certificate, and called itself `bot-client`, and re-used some paths found in previous TA444 samples (as disclosed by our pals at [SentinelOne](https://www.sentinelone.com/blog/bluenoroff-how-dprks-macos-rustbucket-seeks-to-evade-analysis-and-detection/)) - thanks Carey!!

![LeftOver Paths](/assets/2024-01-04-LeftOverPaths.png)

### Triage

Now, like any good analyst, I'm told to hate on binaries written in Rust - we'll start with normal metadata triage and see nothing to hate on so-far

```
$ emit CosmicRust_arm64 | machometa
{
    "FileType": "THIN",
    "Slices": [
        {
            "Header": {
                "Type": "mach_header_64",
                "Magic": 4277009103,
                "CPUType": "ARM64",
                "CPUSubType": "ALL",
                "FileType": "EXECUTE",
                "LoadCount": 22,
                "LoadSize": 2216,
                "Flags": [
                    "NOUNDEFS",
                    "DYLDLINK",
                    "TWOLEVEL",
                    "PIE",
                    "HAS_TLV_DESCRIPTORS"
                ],
                "Reserved": 0
            },
            "LinkedImages": {
                "LOAD_DYLIB": [
                    "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
                    "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration",
                    "/System/Library/Frameworks/Security.framework/Versions/A/Security",
                    "/usr/lib/libiconv.2.dylib",
                    "/usr/lib/libSystem.B.dylib"
                ]
            },
            "Signatures": {
                "AdHocSigned": true,
                "SignatureIdentifier": "bot_client-dff8c6fef1341bc3",
                "Entitlements": ""
            },
            "Version": {
                "BuildVersion": {
                    "Platform": "MACOS",
                    "MinOS": "12.0.0",
                    "SDK": "13.1.0",
                    "Ntools": 1
                },
                "SourceVersion": 0
            },
            "UUID": "16396c63d8de359d88297dbbe9f94663",
            "BaseName": "",
            "InstallName": ""
        }
    ]
}

```

The nice part about the ad-hoc cert name, besides being funky, is that it can often key us into the method names used in the binary. Some more binary refinery magic, plus a native MacOS utility called `c++filt`, gives us an easy list of names!

```
$ emit CosmicRust_arm64 | vsect __LINKEDIT | carve printable --min=6 | grep -i bot | c++filt | sort
bot_client::CONFIG::h3085113054b09076
bot_client::basicinfo::get_arch::hf061d148e9f761b2
bot_client::basicinfo::get_boottime::hc0870d3c6fe4a9f0
bot_client::basicinfo::get_cwd::hd5fe9c5766f3823d
bot_client::basicinfo::get_version::hcf21062a6b7cfedc
bot_client::basicinfo::home_dir::h71dd1dafa71110d5
bot_client::basicinfo::set_cwd::h395bfb5ea3b37e5c
bot_client::decode_string::h6cae7288662dff9b
bot_client::encode_string::h479fdb27cfca5009
bot_client::main::h011099b72ac39ae5
bot_client::process_request::h0de696d02db55a29
bot_client::process_response::h4ff9d2ae3a03e3cc
bot_client::structs::_::_$LT$impl$u20$serde..ser..Serialize$u20$for$u20$bot_client..structs..BasicInfoStruct$GT$::serialize::h49a689625b6d5588
bot_client::structs::_::_$LT$impl$u20$serde..ser..Serialize$u20$for$u20$bot_client..structs..ResponseStruct$GT$::serialize::h9a12860e431b9868
bot_client::structs::_::_$LT$impl$u20$serde..ser..Serialize$u20$for$u20$bot_client..structs..SocketEventStruct$GT$::serialize::h6015da4c41127cb4
core::ptr::drop_in_place$LT$bot_client..main..$u7b$$u7b$closure$u7d$$u7d$$GT$::h422fe17334b326b3
core::ptr::drop_in_place$LT$bot_client..main..$u7b$$u7b$closure$u7d$$u7d$$GT$::hf34a590345c670a3
core::ptr::drop_in_place$LT$bot_client..process_execcmd..$u7b$$u7b$closure$u7d$$u7d$$GT$::hb787796c76fca3f5
core::ptr::drop_in_place$LT$bot_client..structs..AuthCommandStruct$GT$::he39133f0775fb96d
core::ptr::drop_in_place$LT$bot_client..structs..BasicInfoStruct$GT$::h1a0279f220e208ef
core::ptr::drop_in_place$LT$bot_client..structs..CommandStruct$GT$::hf7db62b686c36583
core::ptr::drop_in_place$LT$bot_client..structs..SocketEventStruct$GT$::hc0fc0774c8f9677d
```

taking those easily legible names and marking up our BinaryNinja project, we get some pretty legible high level IL pseudocode and function names!

![Function Names](/assets/2024-01-04-functionnames.png)

here's an example function, `bot_client::basicinfo::get_arch` gathering host information - it also checks if the host is running PowerPc - cool!

![Get_Arch Func](/assets/2024-01-04-disassembly.png)

I have no idea how good the disassembly would be as a YARA rule, so for now, we'll just use the names the malware devs used and keep things moving!

```
rule APT_NK_TA444_CosmicRust
{
	meta:
		author = "Greg Lesnewich"
		description = "track CosmicRust backdoor"
		date = "2024-01-04"
		version = "1.0"
		hash = "5115be816d0cd579915d079573bfa384d78ac0bd33cc845b7a83a488b0fc1b99"
		hash = "045959bcc47fc8c3d4fdfe4e065bfbc18cf7c3101d2fafbea0c9160e7e0805bc"
		hash = "3315e5a4590e430550a4d85d0caf5f521d421a2966b23416fcfc275a5fd2629a"

	strings:
		$name = "bot_client" ascii
		$method = "basicinfo" ascii
		$func1 = "get_boottime" ascii
		$func2 = "get_arch" ascii
		$func3 = "get_version" ascii
		$func4 = "get_cwd" ascii
		$func5 = "home_dir" ascii
		$func6 = "set_cwd" ascii
		$func7 = "decode_string" ascii
		$func8 = "encode_string" ascii
		$func9 = "process_request" ascii
		$func10 = "process_response" ascii

	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and ($name or $method) and 6 of ($func*)
}
```
I thought about writing a rule looking for Macho's that contain weird arch strings, like `PowerPc` but it turns out CosmicRust stores these on the stack, so it might be inconsistent - maybe a problem to solve with Cerebro ...

![PowerPC](/assets/2024-01-04-stack_str.png)

### Wrapping Up

I got no big thoughts today, but Rust wasn't as bad as expected
