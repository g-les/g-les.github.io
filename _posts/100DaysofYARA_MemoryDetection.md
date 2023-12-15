
One of the most useful ways to use YARA is on memory. However, doing so requires a lot more of a lift than what I normally talk about - the static scanning of files at rest, not dynamic analysis. However, since packers and detection evasion change more often than payloads do, if we can get our hands on unpacked samples we can write a signature to find them, regardless of the packer used. 

Enter Hatching & their Triage product. Hatching is a sandbox like many others (they are owned by Recorded Future, where I used to work. I am not shilling their product but whats good for the goose is good for the gander as they say)  

Hatching has two main advantages: 

1. it allows for custom YARA rules to be implemented and 
2. It runs said rules over snap shots of new process memory 

This allows us to write rules for in-memory payloads. 

Now, we _could_ use UnPacMe to get these unpacked payloads. Its a great service for getting access to the sample to do further analysis on. Running the files in Triage merely allows us to get a dynamic analysis on the file to get other pivot points to work with. 

### Getting Started 

So lets go right for an example. This [run](https://tria.ge/231213-p872jaeec3/behavioral1) is a sample of HazyLoad, a loader that deploys a proxy tool into memory as found by both [Microsoft](https://www.microsoft.com/en-us/security/blog/2023/10/18/multiple-north-korean-threat-actors-exploiting-the-teamcity-cve-2023-42793-vulnerability/)  and [Cisco Talos](https://blog.talosintelligence.com/lazarus_new_rats_dlang_and_telegram/) . Neither describe the method used to decrypt and load the proxy tool into memory, and no strings in the binary indicate that it is doing proxy-things. 

When Triage runs the file, since the payload gets run in memory, we can grab region of memory used by that PID from the Downloads section. 

Since this file is not a pure PE (as we might be from UnPacMe) we can just use good ol strings (or in this case, binary refinery's carve printable command)! Voila! 

```
[-] socket create error
[-] socket connect error
[-] WSAStartup error
[+] Success to connect proxy
[+] Success to handshake proxy
[-] Main Thread Create error.
[+] disconnected from proxy
[+] port [1-65535]
[+] %s:%d
Usage: socks4 [options] 
Options:
 -i     ip of socks4 proxy 
 -p     port of socks4 proxy 
[-] invalid option: "%s"
[-] option "-c" ip of socks4 proxy
[-] option "-s" port of socks4 proxy
[-] invalid option: "%c"
```

Now we can use these strings (especially `[+] port [1-65535]`) in a YARA rule to identify likely HazyLoad payloads. But remember all of the things we've said before, like to check file size and check the headers in your YARA rules? This is an exception to that, and usually the only one. Since YARA does not run on carved memory regions in most places, consider memory to generally be a special case, to rely almost exclusively on string-based rules that will not slow down scanning. 

Triage also has its own specifics for YARA rule creation, based on required meta fields. I use the following template for rules in Triage (some of which will be shown to ALL users)

``` 

rule $template_triage
{
		meta:
				author = "Greg Lesnewich"
				triage_description = "GLES Rule: track family X"
				description = "track family X - this will be the title in the UI"
				date = ""
				version = "1.0"
				hash = ""
				family = "zzzzz"
                triage_score = 4

		strings:
		condition:
				any of them
}

```

Your logic will be hidden to others, but the name will appear in all public samples that match the rule (after they have been processed with the rule present of course) and the Triage score will dictate if the sample is called malicious, so tread carefully!  For more, see their [docs](https://tria.ge/docs/yara/)

Also why GLES rule in the description? So y'all can know it was me :D 

Lets spin up a quick rule for HazyLoad in-memory payloads

``` 
rule APT_NK_TA430_HazyLoad_Mem
{
		meta:
				description = "GLES Rule: track HazyLoad proxy tool in memory"
				triage_description = "detect proxy-related strings loaded in memory by HazyLoad loader"
				reference = "https://www.microsoft.com/en-us/security/blog/2023/10/18/multiple-north-korean-threat-actors-exploiting-the-teamcity-cve-2023-42793-vulnerability/"
                reference = "https://blog.talosintelligence.com/lazarus_new_rats_dlang_and_telegram/"
				author = "Greg Lesnewich"
				date = "2023-12-14"
				version = "1.0"
				family = "HazyLoad"
                triage_score = 4
				hash = "f794dd23878fbae2472178d00867302be69df5e5986f2f3991c4a15150a339b5"
		strings:
				$string1 = "[-] socket create error" ascii wide 
				$string2 = "[-] socket connect error" ascii wide 
				$string3 = "[-] WSAStartup error" ascii wide 
				$string4 = "[+] Success to connect proxy" ascii wide 
				$string5 = "[+] Success to handshake proxy" ascii wide 
				$string6 = "[-] Main Thread Create error." ascii wide 
				$string7 = "[+] disconnected from proxy" ascii wide 
				$string8 = "[+] port [1-65535]" ascii wide 
				$string9 = "[+] %s:%d" ascii wide 
				$string10 = "Usage: socks4 [options] " ascii wide 
				$string11 = "Options:" ascii wide 
				$string12 = " -i     ip of socks4 proxy " ascii wide 
				$string13 = " -p     port of socks4 proxy " ascii wide 
				$string14 = "[-] invalid option: \"%s\"" ascii wide 
				$string15 = "[-] option \"-c\" ip of socks4 proxy" ascii wide 
				$string16 = "[-] option \"-s\" port of socks4 proxy" ascii wide 
				$string17 = "[-] invalid option: \"%c\"" ascii wide 
		condition: 
				12 of them
}
```

Check it out with this [new run](https://tria.ge/231215-b7zf4shgeq/behavioral1). 

### Disclaimer and a Warning 

Now, the thing to be wary of with these types of rules is the inability to easily measure prevalence or hunt on how common a given string is. Basically, all of the retrospective things we can do with YARA tend to apply to static objects, not volatile (or constantly changing) things like memory. So on rules like this, I'd recommend testing that the rule does not have any hits in your local malware repository to ensure lack of collisions. Additionally, making the condition very stringent is also a good idea. 

Keep an eye on the rule after its implemented (useful to use the `triage_family` meta here to ensure it gets bumped to a 10 in threat score, and makes it a tag to easily check hits) and prune/remove quickly if it starts breaking stuff.
### Wrapping Up

now, could this rule be more efficient with wide/ascii string delineation? of course. However, this is meant to server as a primer for enabling hunting for in-memory payloads in Triage! 

Next time we'll look at the actual loader component and try to find more like it! 