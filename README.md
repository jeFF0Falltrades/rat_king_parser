![rat_king_parser logo](https://raw.githubusercontent.com/jeFF0Falltrades/rat_king_parser/refs/heads/master/.github/logo.png)

# The RAT King Parser

A robust, multiprocessing-capable, multi-family RAT config parser/extractor, tested for use with:

- AsyncRAT
- DcRAT 
- VenomRAT
- QuasarRAT
- XWorm
- XenoRat
- Other cloned/derivative RAT families of the above

This configuration parser seeks to be "robust" in that it does not require the user to know anything about the strain or configuration of the RAT ahead of time: 

It looks for common configuration patterns present in the above-mentioned RAT families (as well as several clones and derivatives), parses and decrypts the configuration section, using brute-force if simpler patterns are not found, and uses YARA to suggest a possible family for the payload.

The original (much less robust) version of this parser is detailed in the accompanying YouTube code overview video here:

- https://www.youtube.com/watch?v=yoz44QKe_2o

and based on the original AsyncRAT config parser and tutorial here:

- https://github.com/jeFF0Falltrades/Tutorials/tree/master/asyncrat_config_parser

## Usage

### Installation

As of `v3.1.2`, the RAT King Parser is now available on PyPI and can be installed via `pip`:

```bash
pip install rat-king-parser
```

Note that YARA must be [installed separately](https://yara.readthedocs.io/en/stable/gettingstarted.html#compiling-and-installing-yara).

### Usage Help

```
$ rat-king-parser -h
usage: rat-king-parser [-h] [-v] [-d] [-n] [-r] [-y YARA] file_paths [file_paths ...]

positional arguments:
  file_paths       One or more RAT payload file paths

options:
  -h, --help       show this help message and exit
  -v, --version    show program's version number and exit
  -d, --debug      Enable debug logging
  -n, --normalize  Attempt to translate common variations of config keys to normalized field names
  -r, --recompile  Recompile the YARA rule file used for family detection prior to running the parser
  -y, --yara YARA  Uses the *compiled* yara rule at this path to determine the potential family of each payload (uses a prepackaged rule at rules.yarc by default)
```

### Using YARA for Payload Identification

A [YARA](https://yara.readthedocs.io/en/latest/) rule for RAT family identification is included with this script in `yara_utils` in both raw and compiled forms.

However, using the `--yara` flag allows a user to specify their own custom YARA rule (in compiled form) to use for identification as well.

If you encounter errors using the included compiled YARA rule (which most often occur due to mismatched YARA versions), the included rule can be recompiled using your local YARA version by specifying the `--recompile` flag.

`yara_utils/recompile.py`, which is the script invoked by the `--recompile` flag, can also be executed on its own to (re)compile any YARA rule:

```
$ python yara_utils/recompile.py -h
usage: recompile.py [-h] [-i INPUT] [-o OUTPUT]

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        YARA rule to compile
  -o OUTPUT, --output OUTPUT
                        Compiled rule output path
```

```bash
python recompile.py -i my_rule.yar -o my_rule.yarc
```

### External Integrations
As of `v3.1.0`, RAT King Parser has introduced additional, optional wrapper extractors for integration with some external services.

These currently include:

- [MACO](https://github.com/CybercentreCanada/Maco): The Canadian Centre for Cyber Security's malware config extractor framework, which allows RAT King Parser to be integrated with MACO-compatible tools like [AssemblyLine](https://github.com/CybercentreCanada/assemblyline) (though RAT King Parser is already integrated in AssemblyLine's configuration extraction service without need for further configuration)

In order to utilize these extractors, the optional dependencies for a particular extractor must be installed.

This can be completed with `pip` by referencing the specific optional dependency group to install; For example:

```bash
pip install "rat_king_parser[maco] @ git+https://github.com/jeFF0Falltrades/rat_king_parser.git"

```

## Example Input/Output

```bash
$ rat-king-parser -n dangerzone/* | jq
```

```json
[
  {
    "file_path": "dangerzone/034941c1ea1b1ae32a653aab6371f760dfc4fc43db7c7bf07ac10fc9e98c849e",
    "sha256": "034941c1ea1b1ae32a653aab6371f760dfc4fc43db7c7bf07ac10fc9e98c849e",
    "yara_possible_family": "dcrat",
    "key": "3915b12d862a41cce3da2e11ca8cefc26116d0741c23c0748618add80ee31a5c",
    "salt": "4463526174427971777164616e6368756e",
    "config": {
      "Ports": [
        "2525"
      ],
      "Hosts": [
        "20.200.63.2"
      ],
      "Version": " 1.0.7",
      "In_stall": "false",
      "Install_Folder": "%AppData%",
      "Install_File": "",
      "Key": "dU81ekM1S2pQYmVOWWhQcjV4WlJwcWRkSnVYR2tTQ0w=",
      "Mutex": "DcRatMutex_qwqdanchun",
      "Certifi_cate": "MIICMDCCAZmgAwIBAgIVANpXtGwt9qBbU/pdFz8d/Pt6kzb7MA0GCSqGSIb3DQEBDQUAMGQxFTATBgNVBAMMDERjUmF0IFNlcnZlcjETMBEGA1UECwwKcXdxZGFuY2h1bjEcMBoGA1UECgwTRGNSYXQgQnkgcXdxZGFuY2h1bjELMAkGA1UEBwwCU0gxCzAJBgNVBAYTAkNOMB4XDTIxMDIxNzA5MjAzM1oXDTMxMTEyNzA5MjAzM1owEDEOMAwGA1UEAwwFRGNSYXQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKt8nE3x/0XYeyDBrDPxdpVH1EMWSVyndAkdVChKaWQFOAAs4r/UeTmw8POG3jUz/XczWBWJt9Vu4Vl0HJN3ZmRIMr75FDGyieel0Vb8sn0hZcABsNr8dbbzfi+eoocVAyZKd79S0mOUinl4PBhldyUJCvanCnguHux8c2F5vnQlAgMBAAGjMjAwMB0GA1UdDgQWBBRjACzYO/EcXaKzlTz8Oq34J5Zq8DAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBACA8urqJU44+IpPcx9i0Q0Eu9+qWMPdZ09y+6YdumC6dun1OHn1I5F03YqYCfCdq0l3XpszJlYYzPnPB4ThOfiKUwJ1HJWS2lgWKfd+CdSWCch0c2dEE1Pao+xyNcNpuphBraHZYc4ojekgeQ8MSdHVo/YCYpmaJbxFWDhFgr3Lh",
      "Server_signa_ture": "c+KGE0Aw1XRgjGe2Kvay1H3VgUgqKRYGit46DnCR6eW/g+kO+H5oRsfBNkVizj0Q862zTXvLkWZ+ON84bmYhBy3o5YQOPaPyAIXha4ByY150rYRXKkzBR47RkTx616bLYUhqO+PqqNOii9THobbo3zAtwjxEoEWr8s0MLGm2AfE=",
      "Paste_bin": "null",
      "BS_OD": "false",
      "Hw_id": "null",
      "De_lay": "1",
      "Group": "16JUNIO-PJOAO",
      "Anti_Process": "false",
      "An_ti": "false"
    }
  },
  {
    "file_path": "dangerzone/0aa7bfb081e73a67c23715a55ff13a74ef6b1ce2b82a33b5537ee001592919a4",
    "sha256": "0aa7bfb081e73a67c23715a55ff13a74ef6b1ce2b82a33b5537ee001592919a4",
    "yara_possible_family": "asyncrat",
    "key": "564eced38c73ee8089d8bcc951f28c0589a54388a4058b0da1d9c4d94514518f",
    "salt": "bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941",
    "config": {
      "TelegramToken": "7153134069:AAHd4riTPdhAdVGBwo16vJQ5H3eORu5QAEo",
      "TelegramChatID": "1863892139",
      "Ports": [
        "6606",
        "7707",
        "8808"
      ],
      "Hosts": [
        "127.0.0.1"
      ],
      "Version": "",
      "Install": "false",
      "InstallFolder": "%AppData%",
      "InstallFile": "",
      "Key": "Uk9tU0hKZUlVdXBwek1tV3NqYnBLYVRYcklWQXB5c0I=",
      "Mutex": "AsyncMutex_6SI8OkPnk",
      "Certificate": "MIIE9jCCAt6gAwIBAgIQAKQXqY8ZdB/modqi69mWGTANBgkqhkiG9w0BAQ0FADAcMRowGAYDVQQDDBFXb3JsZFdpbmQgU3RlYWxlcjAgFw0yMTA3MTMwNDUxMDZaGA85OTk5MTIzMTIzNTk1OVowHDEaMBgGA1UEAwwRV29ybGRXaW5kIFN0ZWFsZXIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCnRXYoxuLqqgXdcvIAYWb9DuVRl5ZpdpPfoIgmb7Y9A9AuiddKNm4is8EvIlEh98bQD4OBaK0EGWuj7WuAcQPCCGuzHpDqFZbXR7iRqVn6TiLRsO0LCMB4ta4XLQ4JdTFXvnQHcGiUxHddH70T/2P2bBVY0W+PVJDzG3XUWHpYb4PVv7qaQr/DalR3qyyd5otzE1kIjJLCOCyI/9ntIcD/PbMTKVnCP4fzbnkNB+xy0PmQmx3WRWEF5q72TdgaKrCbOpR2C/+rfGIoPC6Ze6dqWO3bQLGt6jpCO8A4CtAaAYmiw1vHUOfP54BgI9ls1TjYO3Rn4R1jmhWBGV2pT5chrglgSxMzPhrxFTQljG78RlPCJmyagJbtnPL3AlV34sQggcbf+80FVeyechm/xrMTSWXrJQ+xek1HRJBDFoCJyUR7SuIUelOW24TU+rwl/2dcALLZXpjYu3/zvJjH4iaJXRCt7oWhfzIFG1bHBFr78kV9VP0H+ZNVb129eUr14F/uubAoIPAz2EHG/CXBZv9GkFuzw0NgsI1eP7AznCLdT+z91M+yB7vWtvclwQ5k6MxWDPOraG5JMjUHvKI6zvyZ4IQ2a7bUENDghxLAqIxgo7zfZMdrjbRxBlqW14oki6Um7GpGKEZ0s2Ip6K2yJHBLpbVxOYjyzrxohMguh+qvgQIDAQABozIwMDAdBgNVHQ4EFgQUmTejTtK6on20N0YJez5sAZdMe/kwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAgEAhauA0si7sHBd06DSGJgP5vJxL2daW30wR5XbAJd0HWj3QWfl7w27iyZ5AqBT4B0ojLNuMUG8mUOvpcoq0m80qUX7TIKUULKvb+i7uGGEDxk3W5F3es/CTUUWO0QlseWx9QEYziGlp6f3tkP4PTGSL0DywVRSa8l6f/B5kqwnW17CbQfJZ8vmy5snpDO/avgYssUnQtKQPhos7GbokNHps/bxEIRfLeprzQox20dw4RV59LcorjP5QV7Vc6FuYmhzC0nfRetTHckyxg66O3ekfTVs87MLiDV0ipQ+D/6k3g6DRuTdd4V2khjtI56ujSqTQ2PueNQXPu8y2fdsT2Rd1LcfxMS1xKAhSwhHfyy0I3JwzPG1D+sm3QNJEOoJviSNn5fYOFpY+mSEkFNMMeEbwOFdHxWbkiJk/Z8VwdH5I52tkHU3sRQMuZHtcKUc/SIt5Ivv6gtuEZQdm1GE6KUdiRB95s8JVGNlCcHX5bXbScu4eKCRQn3Cl+m5KR4EzI6hVP/iDRhVKj7Dn/blOHLzhNS5vW4X085dTP+1TBL8CHpQpiA3t8LfqfV1b/+WahOd3jNBNTXXfe/AQSjErgctLMdmOBpUQaJLOlcDcKGxWQdOo102nxg8Y/kFDARccywugoQxuIZpMYq74tjnJlJZ9kqR/LPrjmvx4v+0XFsaCPE=",
      "Serversignature": "b4TmzraaQMXPVpdfH6wgqDtnXhWP9SP6GdUMgvKSpjPlWufiGM88XWg3Wnv1bduWRMUOAIBN31gAe/SRIhAhdCJU0h6nvqjBUKQsnrg3kT6d2beUtwLDhWWqGa3i9Nta72fkbikM65DIkUwjGtnZy3THx83+doN/+cwe9ZlhKc7TqGF9klOT0nQ9JFUi3Gn6uDzwhA7vicj1WyfM15QxLp0ZvTojgjjFUC2BVkr+mDvuuQ4OR0h4qOgl/AXOYfZwKMfvnwijdP/qqpeG+X73rXZxeDawcTMYqvWH+hOiksgsh2C9V/iN8Sjye/A6rKewmHMUozpakMjP+TjES8kwT70+vJ/uS3ugCZUjT6sOqqLl+LyQyzSpGdVJJQB/fPrYTlWTJwpXdxk8V+eqcdCf/mpeYyQnyGaFVc2whfLAN0r2aPigRQNmsY7Faom/CeNc98zIBf9Nt+KR3FfyFuYabZn5zQcYNAq6D0MVRbKQsU3eyGWN+JI24PQUloheBFJvimpBqMMRVWDLsQq82TpExWJoT47fBrzZj/6LE10vKwl6TNiE81fkglcc93ErbH1KCdXxUaxKVePUIypEaohzXkv88h7P6gjhm2Crey8mUkir408At+5Xl8hQE1ozQN0e5le2gIdxX+oFkTFDrzd65MAdKiZ7rqauNMb4aM+bEeM=",
      "Anti": "false",
      "Pastebin": "null",
      "BDOS": "false",
      "Hwid": "null",
      "Delay": "3",
      "Group": "Default"
    }
  },
  {
    "file_path": "dangerzone/0e19cefba973323c234322452dfd04e318f14809375090b4f6ab39282f6ba07e",
    "sha256": "0e19cefba973323c234322452dfd04e318f14809375090b4f6ab39282f6ba07e",
    "yara_possible_family": "asyncrat",
    "key": "None",
    "salt": "bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941",
    "config": {
      "Ports": [
        "%Ports%"
      ],
      "Hosts": [
        "%Hosts%"
      ],
      "Version": "%Version%",
      "Install": "%Install%",
      "InstallFolder": "%Folder%",
      "InstallFile": "%File%",
      "Key": "%Key%",
      "Mutex": "%MTX%",
      "Certificate": "%Certificate%",
      "Serversignature": "%Serversignature%",
      "Anti": "%Anti%",
      "Pastebin": "%Pastebin%",
      "BDOS": "%BDOS%",
      "Hwid": "null",
      "Delay": "%Delay%",
      "Group": "%Group%"
    }
  },
  {
    "file_path": "dangerzone/6b99acfa5961591c39b3f889cf29970c1dd48ddb0e274f14317940cf279a4412",
    "sha256": "6b99acfa5961591c39b3f889cf29970c1dd48ddb0e274f14317940cf279a4412",
    "yara_possible_family": "asyncrat",
    "key": "eebdb6b2b00c2501b7b246442a354c5c3d743346e4cc88896ce68485dd6bbb8f",
    "salt": "bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941",
    "config": {
      "Ports": [
        "2400"
      ],
      "Hosts": [
        "minecraftdayzserver.ddns.net"
      ],
      "Version": "0.5.8",
      "Install": "true",
      "InstallFolder": "%AppData%",
      "InstallFile": "WinRar.exe",
      "Key": "VUpkMU9UTEhRSEVSN2d2eWpLeDJud2Q0STFIcDRXS0U=",
      "Mutex": "LMAsmxp3mz2D",
      "Certificate": "MIIE4DCCAsigAwIBAgIQAM+WaL4OeJIj4I0Usukl1TANBgkqhkiG9w0BAQ0FADARMQ8wDQYDVQQDDAZTZXJ2ZXIwIBcNMjQwNDA0MTYzMzA2WhgPOTk5OTEyMzEyMzU5NTlaMBExDzANBgNVBAMMBlNlcnZlcjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKhz3rO2b0ITSMGvwlS7uWZLVU7cuvYiIyB2WnGxe2SUlT5/pZrRxfX6CVL8t11S5CG3UFMdKDutLiA1amqLDbkqZAjG/g1J+7OPUOBrBWfzpEk/CFCFjmUTlMPwM00DtDp5Ju8ONc09JiaL9Ni3GeYsXza+HZB0WRrgpKnMNu+833ddBOaIgdvB4KicE/S8hSRq5kTNIhiNNZ0nrMFgzaQj0ijyXNTXN7nFCTqRSkWn/2pdveWZLqzTRZ5HsUkeXr2vhSdrrk7KOpHWjqNr2Nhl+bqsIRUhwnthLhj6N1Y94W25j3ATrLR6mjjZTGI2wRm95bMe/7V4DxqV30i6MVrwYMXKcaPO+NHoF9P1lErhCgttEGyWJz2dVJqVCXA+fE8hLyKSUeJSwaBJ36Of/OFGXXMXpUD7eFHNCN2yPVsW1ogS04/xkQUmbWbRjYx/l02+RK/kAK3YsZDuvcLsbKoDq7XJKoBVfvbv5W7jcmMvHHT54PNbmkAUasbtM/+/KhKQe1etOoYd+gOv7tgcNFRVH6N6eSuTxasCYjCr9tSLLmziNalWTknHgBtL/x49BJw6FWwrEE3wsl3C4ALfHQFbtI6sTLdCk7t/oNFUhpVE4kwql5xtOpYpkAj500jGfmVc9Wjy34tON2QLKnzAO87pt8XyANEFQdm3qUJX56KdAgMBAAGjMjAwMB0GA1UdDgQWBBRP67T1n4GPr5zJ0tsXMJ+gL7IawDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4ICAQBMOPQsFZRxqhZZ344n0qBiatzq/jSmfMsMKWYMTiFHHccrgSc63C+nlVpTSCys2BZaMyocxeWKI+w7NklntQhp058+oN7PVC87xod6uZQyfYG1oCR58+Po4I3lWHVdOWQrkEKf4LTpCtyPXPTccZL3AjYcZWLOvP0gcjRsF2dSGnN1WdTPKHxj+OLSwSxlwTW4WN2wg++OV9cmT4wgaT2jPDqv3twxV+JVwEeXMM7XthJsG8ajToCS3Sf7pXnuOBIBoITQEbi7Iyqm/mJwFmAkcpEXb88rHZnKs+rRzjPRI/XsvlGVVuyiHtvPJL9X+R3VVltvrawBCbmN9K2W21E56Nryip0q4wdcF1jJUHXxAiQo/jcu8fO3RGfs9I6SN54PXSWABS7MvNJU8njC1N3J110cnjTgVMNrgRhBHe6r9CGnN4gm9oKvKL5+0/zZvhUPgYusOHIQmdOdfLo0r7tckUk2D18ufRILcaOqyaHLI7Mri1XEli8Brfjdtv/dlpssh/B2/o3bhBlRVD4oL+EX71Bm6cHEKoCLL6zGySSQosQyZpR2j4qVObb5fK1EnilJG4Qk6mNULZfWVPD9TLsJTHEioV8GibykF5O79kruha/pxFvVnoDJHbTPZEWfuR4cb6YIFbTg9pJrOhUsoyZg41leCrcqHR82XOVB755xfw==",
      "Serversignature": "PBjqcvsYypDmnjgUVv1SkvtLx+jFt2V7NyZ+nHik0CWcLbwOwBXD6/3an89d/I7pFAxwZXgSiLunc1yCOocUvymhbMwqT5t/yuj4GdW3a16vZSUuPbvGEOuB2oCgUNrsLWzqshnd1yaTIbNoENLJNS3phGLnQXijbrE2/mSEWbSjLcCWMC7Q52c54RCiBuKPQEhFR1KMUBtSeskObCEqOKY9tYsKKTDYDrQPp32Ho4qArPCDIiefcNiT4k17Dw4srW1OkC3uhSCc7BV1dZA/HJw5gd34pFTeCnJnqY34OmE7sux8mhBjaIXSJMXD81272ngrmGwu6++6DkdLgIx2y3uE6IcUFDQmOgU6T9I0ulogZGGZa1PI3VjBjF4TK27EwzrkR0iKi8Ctn8z/HMXnskviCaui6RlxEzWqOytSfe4m0XHpNN2gHVhKbZwJUr5IwKASOWiXgsOVpkTn8K6PDN22X2rCUigjRsE4/45qhd6BFCa/pXMgCHljHKi5qp13yor91rO9n6NjbO2bP28cexUmUwf03lClGQ2og8q05WWiqHHvLlpHxmy8fZwzniJC3tr6htyPYhGpzo20BMOz/x66tA/+JTC8CFFilvf3PP97KwfqpVNqtnyHVui7QR39E6QvoyNzw+7AxpHCSYx6F9tyWu96pBeSbCrMzXaSV0k=",
      "Anti": "false",
      "Pastebin": "null",
      "BDOS": "false",
      "Hwid": "null",
      "Delay": "3",
      "Group": "Default"
    }
  },
  {
    "file_path": "dangerzone/83892117f96867db66c1e6676822a4c0d6691cde60449ee47457f4cc31410fce",
    "sha256": "83892117f96867db66c1e6676822a4c0d6691cde60449ee47457f4cc31410fce",
    "yara_possible_family": "quasarrat",
    "key": "ff230bfb57fecad4bd59d4d97f6883b4",
    "salt": "bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941",
    "config": {
      "梽畨芾⇼범䨖ꔭ⧭ㅙ⢄熼ꟿ⼳᷍砫ᡸꟿﾼഹ": "1.3.0.0",
      "ꥄ챥蝝࿙ዷ䑌⭞⿑㦝䜒䖘苘ꃧ읲㚥ᡄ媬": "qztadmin.duckdns.org:9782;",
      "蚹嘪ꜟ쀣쓡爲劄㷟耑츋϶�૥ὂ䲬㺲釺罱恫ῗ": 3000,
      "姰쭕锓
滧ꥀ栞丫갣橶譌窴׮ꄩ邪᷺": "1WvgEMPjdwfqIMeM9MclyQ==",
      "αХɇらꁶꄕ搩〆ᮍ뽭⩖覮ϕ鷫Ꝧ겈屄롚쐢": "NcFtjbDOcsw7Evd3coMC0y4koy/SRZGydhNmno81ZOWOvdfg7sv0Cj5ad2ROUfX4QMscAIjYJdjrrs41+qcQwg==",
      "맻胼䇸ﳊ㒡蠯칣ᰶ⇷敉謵완瀫ᣣ究హ": "APPLICATIONDATA",
      "딕漩럙褹퍵ᮐ螉뗏흛ᅩ駔졾楝팵᳦ꔍ퓩": "SubDir",
      "楤쿄ㄕݮ㦲／ⳡÀ阙楞媾⯥舶㚽侕넉䜠൱胍": "Client.exe",
      "ꦶ◊ꇔ㺺⫺黆⋚㩼﫯졮瑭篛싧礞ᛂ卵᠃": false,
      "雒ﵚ푨繏�剷ᬬ⵪�귯죥羢ꊇ鄬譆屿靘绠": false,
      "뷉෢ᬚ杤羾姣籼䏤卢꺢鼕�좖Ⲭ때믩ꯪ캖": "QSR_MUTEX_YMblzlA3rm38L7nnxQ",
      "攀㿘왂㩋᎟䓿䕔�د州쯲ꀈ级䀇�ﴍ哚Ɪ幒": "Quasar Client Startup",
      "䞑隌ᇅ欉ᅈ킅杖蝬䞂鼿⡮뀾鉛췡罡衅쑈": false,
      "鶹鱶ꏭ¥쒥녠⪚㐢ꔶ�㗬쁫ﹰ깧냁鮘ఋ鄳": true,
      "녝맯넰鸸莨둑⤘㔒荲뽓⢕⢏幧皂힫ᯝ䩴鵔邫꾈": "mDf8ODHd9XwqMsIxpY8F",
      "�荣ڲ蚘騌殼㫔រ볡༭误펮頠䬡�硲욣": "Office04",
      "Ꮞ㮇泄쮬櫌⦤퀼뜸姭퀏锖鐓躲罸멇〃": "Logs",
      "ߢ訴ﻘ篋껫슴㹞ᢡ尖Ť岺ፇ庵�獍ᇔ哜ﺲ暽": true,
      "祹륰㫬�伫蔩⍭䧇芕㵼鈍䰸з䘶蟨庛쵃턐": false
    }
  },
  {
    "file_path": "dangerzone/9bfed30be017e62e482a8792fb643a0ca4fa22167e4b239cde37b70db241f2c4",
    "sha256": "9bfed30be017e62e482a8792fb643a0ca4fa22167e4b239cde37b70db241f2c4",
    "yara_possible_family": "venomrat",
    "key": "86cfd98ca989924e7a9439902dc6a72e315da09c11b100c39cd59b9c9372b192",
    "salt": "56656e6f6d524154427956656e6f6d",
    "config": {
      "Ports": [
        "4449"
      ],
      "Hosts": [
        "127.0.0.1"
      ],
      "Version": "Venom RAT + HVNC + Stealer + Grabber  v6.0.3",
      "In_stall": "false",
      "Install_Folder": "%AppData%",
      "Install_File": "speedy",
      "Key": "TzY1S0thald3UGNURmJTYjNSQVdBYlBQR2tTdUFaTTg=",
      "Mutex": "ypxcfziuep",
      "Certifi_cate": "MIICNjCCAZ+gAwIBAgIVALWZXeRliC16frxuoSrGsVJO4U2tMA0GCSqGSIb3DQEBDQUAMGcxFTATBgNVBAMMDHNwZWVkeSBkcmVhbTETMBEGA1UECwwKcXdxZGFuY2h1bjEfMB0GA1UECgwWVmVub21SQVQgQnkgcXdxZGFuY2h1bjELMAkGA1UEBwwCU0gxCzAJBgNVBAYTAkNOMB4XDTIzMDYyNjEzNDc0OFoXDTM0MDQwNDEzNDc0OFowEzERMA8GA1UEAwwIVmVub21SQVQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJ2DCquy6CwL8H/T1Wi72pbKLyGQdoXBDSKpGyIfLgX5091jBQYbvFbROqt6FjbN52GSpnmd4N8TnQE6KGqTmmSmaf/nxMSNcV1sjhxm7NTfnP9vo/vnZngCmzVr91S9REqlKCiotdkIYWqbdwkmYTuqSdHaicP7Tf0H8oOYZIc5AgMBAAGjMjAwMB0GA1UdDgQWBBS/OFCWU/dcBWOe+i6ERcFdHDOwITAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAIT79sUZm5Je3T7yc9GS+pgzsgtf8OXakm0DrY41uytJgXzgi2E/bWIBja4DyuAddL0ziDCamqDQuFA1MhFNki/X0uKgu1ArxZeXlwKqpDv7ihWRqWrE3rHYha0ALSP8DN0Asmpc4FGnrfhoeoLYXRo8EqH+6ctIkggM8OiBYSTm",
      "Server_signa_ture": "Sn1WeJuN+Ypb6kUw4QirT1RzbwUEoeSYTmJAIlg0LayMd/VSwAo+0LnnT/g5HFx4QrqaM689CvKqUNfotQb9cPj05dfgrV3SplVDt5twnK6f8nnScqI8trTCmprH1gnOcoKcY8039kFo9dEj+eOiaBF451W181I5fPJd4Uug1bY=",
      "Paste_bin": "null",
      "BS_OD": "false",
      "Hw_id": "null",
      "De_lay": "1",
      "Group": "Default",
      "Anti_Process": "false",
      "An_ti": "true"
    }
  },
  {
    "file_path": "dangerzone/a2817702fecb280069f0723cd2d0bfdca63763b9cdc833941c4f33bbe383d93e",
    "sha256": "a2817702fecb280069f0723cd2d0bfdca63763b9cdc833941c4f33bbe383d93e",
    "yara_possible_family": "quasarrat",
    "key": "None",
    "salt": "None",
    "config": {
      "Version": "1.0.00.r3",
      "RECONNECTDELAY": 5000,
      "PASSWORD": "5EPmsqV4iTCGjx9aY3yYpBWD0IgEJpHNEP75pks",
      "SPECIALFOLDER": "APPLICATIONDATA",
      "SUBFOLDER": "SUB",
      "INSTALLNAME": "INSTALL",
      "INSTALL": false,
      "STARTUP": true,
      "Mutex": "e4d6a6ec-320d-48ee-b6b2-fa24f03760d4",
      "STARTUPKEY": "STARTUP",
      "HIDEFILE": true,
      "ENABLELOGGER": true,
      "Key": "O2CCRlKB5V3AWlrHVKWMrr1GvKqVxXWdcx0l0s6L8fB2mavMqr",
      "Group": "RELEASE",
      "hardcoded_hosts": [
        "kilofrngcida.xyz:443",
        "sartelloil.lat:443",
        "fostlivedol.xyz:443",
        "comerciodepeixekino.org:443",
        "cartlinkfoltrem.xyz:443",
        "trucks-transport.xyz:443"
      ]
    }
  },
  {
    "file_path": "dangerzone/a76af3d67a95a22efd83d016c9142b7ac9974068625516de23e77a5ac3dd051b",
    "sha256": "a76af3d67a95a22efd83d016c9142b7ac9974068625516de23e77a5ac3dd051b",
    "yara_possible_family": "quasarrat",
    "key": "b30cea630f7fac6c2e066ce7f29e1b4bab548ee95b20ff6aa7387ce14df5dc30",
    "salt": "bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941",
    "config": {
      "寘褂䪳ꗉ銗�Ꝉ镋堁쳚燱猔畏‶픘㓄௒꯼": "1.4.1",
      "뵴ꊲ袹裸栊渜鱗�缝糖궝镀ƙ衹摂䴧슖": "10.0.0.61:4782;24.67.68.3:4782;",
      "꼲僭퍟脖ꄀ憪䑪띊�ဩ螥鰲樭搼┵�": 3000,
      "轢䨉攀轣ꄨ훨觅뱛㇍昺灊䔱䩦菼䪖〪븱뺽᧨˸": "APPLICATIONDATA",
      "߯꬛빅咨蝍철礍庌縴猏脋刏纋蜘᪱䏬렝": "SubDir",
      "᭓ⶶ穱׵ᗾ嶻푞셣쏵爒얢쳱䖨䒉鄛": "GloomTool.exe",
      "ʹ᝞씓鉀ᵝ덾稠緘ᜉ棴桛ਃꢒཡ卫͔뻇㯨悕": true,
      "컸�퍲愛欷口쏘푂샊ʿᑷ苽⑉젫珝㆜䨼ᵆ辘": true,
      "嘂ᢾ٪ￆᅭ筱凶옿嶻ﭡ࡛୭ងⒷ娩抢落": "9fdd3e80-d560-431b-b526-3ebbc1799110",
      "鿴�蚿ㅃ쟄ᾚ넕蛟须ꁅ㊇摯킋拞뻧≰Ḻ럌耇": "WindowsAV",
      "뛊㕦䆝ᝢ啍⦙♉曗긿ꆨ෶嵈�ࡡᎆ淯枍岽귌": true,
      "汄똉检풛鸨远⡮뒳屮䪹ﾢ筎ڹਧ軘癝렗䠉澬": true,
      "ꭂ㣠췼ਠ韷ᔅ놷崘姃㛱꜊躅풉ꎐ⌽꯿㱶⥴": "5F91B88C67A9ACF78B2396771B3B6F2B4615CA57",
      "숸윓㎊淘ꥑሺ࣓䷢㓦排溳昀讓퇾䯪훲�࿅": "Office04",
      "맖⟑ᗽ敥悼�끻둅薿䴒⎯�坦챹탏琅㟘乄": "Logs",
      "⣿嶤먂㍨̑패熟塾䂭᪾�벃ｉ�ᒉ菜ࢧ": "KQrwmpZSwOF20ZdNZlVJ7YjgErzUf9cophPOCAULRI4gSid7qeSaRL4LhhUXzEq1JuUlkRR7WTjztBsmwCRqORdxEBFwd1fMTsYFf4COj4yN1sbvc5Yb1qvk6IELnzse14eXVS+y1AbwCOGBEa1P6H2C2X2xH6jZRBMPaFsohcV0z20ZzWpdJw+aQZ/SSbMvE1YFN5o37y3MzAW/nErdZyxLA7t9eTsca+RLT8uHgqU0iEd4Mz1iHUWA2gYY+uPzV1I3oU8LHrWhXnXRhutbShZ80KbE+tfr7XLAIwwol00moTd7GaL4vd/ZeOa3z3nmVO2GxIRMWCmiX52l5MutcuR/nAAR1k+W2ScaAoxXzpb6pwOwccooFty0lpRoO6RMT+g1ux+jwKn4RpH1baEAmA6cu8W2l1mr8dwZ3ra094dUKEdITKRKEviworYIRWDS9w2618tVfRhccHNsbIIp5qZMumne0OVE+FK6rjPZM/Q4OR7++1AQUNiavCOsY6/sbxdb+K43x2PrxzJAPoU33qF2fzXaSIEgbmlqkZFdFOhSVHay5F4lmuvHUGRXmhs37quo874DaCA5phI3aCP8VXIFkHyjOJelIR9wlfsdNY5yOoA2POnFt1Y24YzoPZt3Mc/Nqv74z/cE3LXrJHsgivyZV25nqpiCHL704AfoRpo=",
      "﫪䤈醈慆싔䚾樎搅쳶稶셜嶺ᤧ朏ᅾ㸑㼿홤囸": "MIIE9DCCAtygAwIBAgIQAIhqXB+nLwd+VvEk3rjLsTANBgkqhkiG9w0BAQ0FADAbMRkwFwYDVQQDDBBRdWFzYXIgU2VydmVyIENBMCAXDTI0MDQwNTIyNDkxN1oYDzk5OTkxMjMxMjM1OTU5WjAbMRkwFwYDVQQDDBBRdWFzYXIgU2VydmVyIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArk3R4LAyzBp+YXIUqxBNyT/R94en+jU7NTtJGsCG7I6Tp2ZV6mdTOynApeBLs6RvgIpzxPIbjA7HMoQqRxBDKREcRZJCnK3NdMl+8ZMKU4OLBWINwW4fvZRu2spC79MYiIsKOXRDsfCelPs1llHTbD4b4c+PzbpcGA5gI+luZ6+OKajkGbAKdppse5EdPh+KrE6r74nAJiK9PdvfF1H7XwOVpFChxcYZJmZTG8hfrSFQ/0mSi0CobU71vj8fVkhX0EOVSv/KoilBScsXRYbvNY/uEzS+9f0xsYK5AgJQcUYWLthqKSZbo3T1WecBHKynExf8LbFpC42ACyPbZXtAYt1lyBXyLW8TZS65yquhcVio/ZgAG05WGn+TeA6M+CxNkEZNvgd5PDuBkF6X13w3OXGFOL7i4KBJifSMRyJaqp9i6ksAY8epDRHP1WOXDxnQ8ak+4jyPC6WSZFnGV3DT7lZahvkIaNR8OPR8suOoUWk8Jl9Fxx+DBa6RK3Ht96YkPAf8rY84Hjjp4xp1OF6q88W1YaYo9NtPK+5fkf2pFqa+RC7v3RKgsis3/1xYeBZ8expiCdm5hKTRx0tAkG5bLzC6/Em8cHqCR6lmbPuHgA4ijByU6fLD1JdmwqAcjpy9OIdB8L+G7X8kAu5+WUe5BMiIE6EYvJi3Rpg2fz5Nt9UCAwEAAaMyMDAwHQYDVR0OBBYEFI40k9gCti/BlRy3dUVqsbe3OhMxMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggIBAAXYckulFdYnmtdh24egkttF9h/0AD87o9kAnRwJVu3nu12R+FwJgaihvAQZiKQ4kgTkP//ag9E60xwyzEcj00/yZGzjMAAXONZoEyeCxEF5cMjbtmqLWsFkRaHEpWtcczJ2BChEnFDgoGF2I6TOlr7OGoJnzHmz43bY9dkpDJ+tqIZu5AwoMG4WMoNe+by66G2S1AjyVVimIJA7at12EMIUizO0Qov+iBFHSDiVwOZlUxhfu9TNKwIgQdSLHnTaBg03VFHpLZ63Qtmr12LwTEOUyVSnJXEsgZISQ0abMCaped6jwpR7+VlpU4SGfyBU8caFphJafdgVzhmztrTpYMUJE44d50+5ue9us2H2IH+26/+yBbQdffzp1LAFfYgjOE7k8EFjU3ayPaTN7ORtjCyNzhYRvjUCuopb0rWhJsQQRQJzkblrYJ/ocSfNGUQOoJpykyD1QiGboE11xIPheLYetZrRtkmNtFuVeKg9z7AB1ahxEcNGT/MW/wkxUe500cBLVTFeZtsMl7WYB6iUSxboQ8zZ8eWCDS2hYOxKfxfr54p4AW24Y267djKnAfpnMIsgJzjcDxvGGMBlwcrxb0vM0w+9K2R+M17r4bldxnStJj2Wtgal1TBVP1XexZgarfXw3HstKjhbFH6cb4g7ZW4wdCYE5XA6qZL00XpuSy4t",
      "撂嗌ఀ渌냋✹엳!�暐쀗삚瘣괫ꝥൡ珁䭦䎍": true,
      "ꬪḜ錌⧥琰锜艑닅썳宓幂죺䦛�ឆ輶跂椦": true,
      "뉻퉰�㕞ᘢ甙鶖獤짐῞助멁ḱ挒豷⫟ᚊ룪慁樟": "",
      "䱲讀��ꞇ䥕鬛�行ﳄ坄딧頜쬥禸竚⏺": "",
      "剔壴昚켜꜁⽳彲懔嶥顣硝芹憖麖满境꡸": true
    }
  },
  {
    "file_path": "dangerzone/b5bff486f091f9539606931e0aff280eaea17064b2a12940675dfac926e9666e.exe",
    "sha256": "b5bff486f091f9539606931e0aff280eaea17064b2a12940675dfac926e9666e",
    "yara_possible_family": "xworm",
    "key": "c527ac2a4eeb6039d9477583d0f4f2c527ac2a4eeb6039d9477583d0f4f2ee00",
    "salt": "None",
    "config": {
      "Hosts": [
        "act-cleaning.gl.at.ply.gg"
      ],
      "Ports": [
        "37158"
      ],
      "KEY": "<123456789>",
      "SPL": "<Xwormmm>",
      "Sleep": 3,
      "Group": "NeverLoseCrack",
      "USBNM": "USB.exe",
      "InstallDir": "%ProgramData%",
      "InstallStr": "svchost.exe",
      "Mutex": "OkWVOTioL6k3Fg3w",
      "LoggerPath": "\\Log.tmp"
    }
  },
  {
    "file_path": "dangerzone/beb1b5cd2a33e86e48599b183b882fc3e80198a8062e5b9d9251e605d3f0bfd5.exe",
    "sha256": "beb1b5cd2a33e86e48599b183b882fc3e80198a8062e5b9d9251e605d3f0bfd5",
    "yara_possible_family": "quasarrat",
    "key": "b5580a84ddadcf548713dd64fedbbe067f931e6ce4699271de572acbd52f4074",
    "salt": "bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941",
    "config": {
      "伔雂婀瀿ਟ昄뒢셟῔�혞㯫僝큧絜錀䋽쪖": "1.4.1",
      "�냖胃櫐턌㙥਍珃⬆郘⫝̸ᔔ겿꯽㓣玌䠾镲": "91.92.241.122:6969;",
      "䮱⛴�ꓞ獐㲚앮᫷컨ᶉ綟㝬㙚ල፞屷烅": 3000,
      "숀덆衏ꪑꉴ闦ж윰쬁誁㑇�푈ꊦⵙ鼭�퍽닢": "APPLICATIONDATA",
      "ꀥ튪﴿퓪僗䵊㹂溳ၺ렦�坧⬖ﯓ�驨㼂㏜좟": "",
      "ʼយ쬀믍��᱆贘好颗賫柊┩钵ʌ멃B螑䭏": "Client.exe",
      "ꧭꇶ魶䣈ኜ瘷笵ۯ畉錡읐ᛛ箶웤㑍髌�옍": true,
      "斐⛊䒿௿鵂ʁ㫔헊遁骗ꊵ㣉ᚏ㳱鰸࠿䵙깿㒬": true,
      "簔쌑饶曰姞耣㎹䥶鯹ꏃ揼ꖐិ싟캥伽": "fcf2be0a-a426-40c6-b153-1a354814f80d",
      "䃦瑸䱌籾쮇ઈ帝蝃黱䥤긂�듗ሽ엮�ྋ螑�": "Quasar Client Startup",
      "鵶ᳵ䰑訵ᶻ㋪据⽇ደⅡ䒯ઓ夹ዞᛀ뾱᷵鎘뜯": false,
      "㙲輁絫䲖䲎崛婘㨁웳䓪視䈜豇ቊ竭䗹⻼菈鍵": true,
      "㘎▒鏢㣗륾者梓勄鋭Ị秩䴰䯾獵㰀ඇ蠔": "26A6C07FE7354BCD244B108D2E3538DCF04477F5",
      "凷킃瓸䲖ꩾꋷ烿筸駸쉗흋㧃ۛ䃵澶浟뷬䢑": "Fab",
      "ཆ빉뤺뤨刄ꕓ坨迄湎鯙⫵ﰿ䆌᱄㿐έ⋆㕈嗎": "Logs",
      "ᚒ宋㽾亞꿷牣㴳덯蟭빉恷뼞櫻빜ꖯ�꒳ꖗힻ": "U/jVlmjpH/9zMrLFla8LcLavxUQe9wt9L6qGAh9zYqPdqDW0e0fRlnxEST/s3HTVlAyuqIyn5yKrWKaXCMUHKcjpAWVQ9jPLAteKNgIRz5Soa8qxWgD215NTswSL/tYwdPW2svV9y6ELPKScSacDyZlBp47bv299XhxjeUkAXIli59EHnHxAIlOS/Ag51onRTlEkGYIVQO1IJjGoGQe8pND5JwWOVi072s67A16SNYJmPrCNqDjCMVjYDRwLqusbuDPF2K0wIVLn4RzLr+F1O5e5Rh8GFIj/7qa8gOy2kjAbczo3AAKZG3sghrut27P2ldxGcWpsms5w97k7WJ91goBms0n/hV29sRDiYG51xey3KqcTp2UspvLUzNJek21CZk+EgCQ3Q7+aZxdLAIEfwAo0cq7lJkq3iEZuZ+86sts1D3YToM9+mRtIDAeb/op2oxvWbJOqeA9YME2A7PWDVI6bH9kcru5UolqfxPRIH7Aa8BVzAbctghbaVZCiwkI0lxc9hijCLZugOnKXtFU3A+hPVyc/aDqZcWPDu7u9jWbrWIk6JqLGbnJYiU6a4p7IwdGnVwkA49aD4ZnKqWo8tSKLCd+dvP4nx+pqYWiUpf+rdy/xH1MBbPj/lPlphmrFFHijlBufVoSLa88/rBv+Fb9ox2Ei2t5RJYTLDEoP0oY=",
      "䨧猣∣୦�稜⚉柨暁즛쿾坯똃톺ﻬႄ": "MIIE9DCCAtygAwIBAgIQAJMC1KOnf3PAJ47sO2MclTANBgkqhkiG9w0BAQ0FADAbMRkwFwYDVQQDDBBRdWFzYXIgU2VydmVyIENBMCAXDTI0MDgwMjE5MzAwMVoYDzk5OTkxMjMxMjM1OTU5WjAbMRkwFwYDVQQDDBBRdWFzYXIgU2VydmVyIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAk9yV4zXwIw2x7ZZyu2WnaWGwrq2laEP44y9HMM/PYRQCmkMr/L4bqPIgee+trkTOK2T/yd37YISYQSsfQXONYG5JZy1DsZgWAy177xEUoLNAv/TmWrovdVhFSIN0FtQo4ED1AMSOeRWPYw3fdFplPo25TqiZnJuC76fu04Sfl5/B5RqZUy3FKkVlZRL/99zAKjQvFIFvX/riz7pwYPoKSNzRB+SPebLJgYlG7qaxb11C/oiJu1AuEcrmjjr8Ph/nYAqY4EzsjWw6mBUEKTAdCptz78Xpj2qZ/DO//6rDIkw2HWyvvJ4qC2jhv4d2LL/LVSof2SDkMY2NRweMtwnmI8mYIf6mF6pOuH7l6IONc+W2LahqbDImjijmYOJnED/4mV3QRvXHZlwwn/qwf4Fc98VdNayqw1SdKyWqSEIFaa8ZtbSvGj1RQWwzJXQ0sr7EVcv26GUorfX4y5wXhVu5DQfAIZkhZoGSOUPVh0E/NnSqFA10M7TcTz0+fwxLjZ93vi0D0dBcyWvMwTUjy1FHZMu7ZXPsrGbDMmhwmNSsqCqV3SGLZEwaSI2Wtzi1SgElz9+GSh3twxi6O+kaOtP8vu6jbzYi8QSLbn+APkX4XXetIms76fRT6c0yjgnr8NNhdATN3NIAy2AIBfRB9+WkmEEzWf35oLIb0WaNIXtRS5MCAwEAAaMyMDAwHQYDVR0OBBYEFJnfWehSzSmr6K0SenBX6AyNEZUqMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggIBAEsJnW/h1UmS2DsvTd6vhMwSVZjtK5PKYx8HRL1KPrhDa4WVdYvXu9DaO0BHs5dad+EMTuhWirWXv1oG4TUBVwwZ9ka95ooIZhrZdjLe1sXHeRTubU9yO5bl/6fhHUvPcDsktCgBxboI40t6YcJk+wtIdobhhO0dIHK7OAkJMXQMv7bWX6xy2HwPk0tzkHSskWe160kUiNdxZomd6VSL5FnJ9aB6erznl1WABJNRNwIksM1xlrgyCFAMRvJwpJi823H/ApWwAosQo9qstOo2e+OMrCAzexGJL93JANAXAf7xa5TXzcTPd+n9QhYSDWW7EqDim8vguQzHkHkDNRMP0poqTHFYovcupr2zBjkhPC6sP/f0Rq/aQ6Dyqqoj0cW/nH2wl4eFXvQnSHTbbVIo2qzb+Ud1qFhXxkGzuP//V/wBgEAhLcFraqgQ/b4kX0hkhV0yYaTWpqVemg4Aki7RYz9nGIRMcdr+APFeXo49FHjerk0lqszbKd6IJn3CR9U+ZLpzp3M9NLdeTPpjGal8IgMjuO6MXmt/ybz1fAfM0shKsq4+3nUI0TMGBgYhrPdS5VoA29Xg84hAVj7wewNZKJ43d/poHQnrjWkuN/Ii66IaKVyKofoMiHyfHIy0ee456vDYvxbPv+k9euEhv4OiK8dTWwvDr2XlJZWfq+pukDEk",
      "嵥帐迉ⷹ윱ㅥ䢕⎥┷ꀵ쨊ꁌ샖쮟铒﷼㥺쿡茦": false,
      "ா巪騸䑥髲鷞뚒猌鉦扆켡⊸꜉༾⚾龔薮": false,
      "ﺖĊꠣ㬿蔭䮕労酠⏻ꜜ簄ꙡ蚼좦⏺脬럌팩㿑": "",
      "㝉늣漊ꩁᤌ몤뒦짚햻ꙝ꯸㫒뉂摝㘢롷㠨ᗪ": "",
      "ቼಎ绒乫�患㷕㿧㬣翔ḳ⛫ﱑ氖ᔖ졞薿ᐛꨛ醅": true
    }
  },
  {
    "file_path": "dangerzone/d5028e10a756f2df677f32ebde105d7de8df37e253c431837c8f810260f4428e",
    "sha256": "d5028e10a756f2df677f32ebde105d7de8df37e253c431837c8f810260f4428e",
    "yara_possible_family": "xenorat",
    "key": "650f47cdd14eaef8c529f2a03fa7744c",
    "salt": "None",
    "config": {
      "Hosts": [
        "77.221.152.198"
      ],
      "Ports": 4444,
      "Key": "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4",
      "delay": 5000,
      "mutex_string": "Xeno_rat_nd89dsedwqdswdqwdwqdqwdqwdwqdwqdqwdqwdwqdwqd12d",
      "DoStartup": 2222,
      "Install_path": "appdata",
      "startup_name": "nothingset"
    }
  },
  {
    "file_path": "dangerzone/db09db5bdf1dcf6e607936a6abbe5ce91efbbf9ce136efc3bdb45222710792fa",
    "sha256": "db09db5bdf1dcf6e607936a6abbe5ce91efbbf9ce136efc3bdb45222710792fa",
    "yara_possible_family": "venomrat",
    "key": "11ed70df5ce22de750c6e7496fa5c51985c321d2d9dd463979337af003644f41",
    "salt": "56656e6f6d524154427956656e6f6d",
    "config": {
      "Ports": [
        "4449",
        "7772"
      ],
      "Hosts": [
        "127.0.0.1"
      ],
      "Version": "Venom RAT + HVNC + Stealer + Grabber  v6.0.3",
      "In_stall": "false",
      "Install_Folder": "%AppData%",
      "Install_File": "",
      "Key": "M1NoWkREazBvNTNGUkRlT0s4TjE1QlRRQmx4bW1zd2U=",
      "Mutex": "qmhvogiycvwh",
      "Certifi_cate": "MIICOTCCAaKgAwIBAgIVAPyfwFFMs6hxoSr1U5gHJmBruaj1MA0GCSqGSIb3DQEBDQUAMGoxGDAWBgNVBAMMD1Zlbm9tUkFUIFNlcnZlcjETMBEGA1UECwwKcXdxZGFuY2h1bjEfMB0GA1UECgwWVmVub21SQVQgQnkgcXdxZGFuY2h1bjELMAkGA1UEBwwCU0gxCzAJBgNVBAYTAkNOMB4XDTIyMDgxNDA5NDEwOVoXDTMzMDUyMzA5NDEwOVowEzERMA8GA1UEAwwIVmVub21SQVQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJMk9aXYluIabmb8kV7b5XTizjGIK0IH5qWN260bNCSIKNt2zQOLq6jGfh+VvAA/ddzW3TGyxBUMbya8CatcEPCCiU4SEc8xjyE/n8+O0uya4p8g4ooTRIrNFHrRVySKchyTv32rce963WWvmj+qDvwUHHkEY+Dsjf46C40vWLDxAgMBAAGjMjAwMB0GA1UdDgQWBBQsonRhlv8vx7fdxs/nJE8fsLDixjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAAVFFK4iQZ7aqDrUwV6nj3VoXFOcHVo+g9p9ikiXT8DjC2iQioCrN3cN4+w7YOkjPDL+fP3A7v+EI9z1lwEHgAqFPY7tF7sT9JEFtq/+XPM9bgDZnh4o1EWLq7Zdm66whSYsGIPR8wJdtjw6U396lrRHe6ODtIGB/JXyYYIdaVrz",
      "Server_signa_ture": "BW9mNNWdLZ+UgmfSTOot753DE24GfE+H6HYG5yl4IFszdMLpfQXijxVlt3bcz68PrHwYG2R70J+h9EVUXPjNw2GgCH5I8BvOw6Luh09VjE3YrfERSa2NKJ7baO9U9NDhM4HaSUCUvXGbR6J0itLe+2YthV7GXSCEbbmfZI9UYKU=",
      "Paste_bin": "null",
      "BS_OD": "false",
      "Hw_id": "null",
      "De_lay": "1",
      "Group": "Default",
      "Anti_Process": "false",
      "An_ti": "false"
    }
  },
  {
    "file_path": "dangerzone/fb0d45b0e48b0cdda2dd8c5a152f3c7a375c18d63e588f6a217c9d47f7d5199d",
    "sha256": "fb0d45b0e48b0cdda2dd8c5a152f3c7a375c18d63e588f6a217c9d47f7d5199d",
    "yara_possible_family": "xworm",
    "key": "e5f7efe2fddd6755c92cbc39d5559ce5f7efe2fddd6755c92cbc39d5559c4000",
    "salt": "None",
    "config": {
      "aumDBZNDJ7f2": "mo1010.duckdns.org",
      "gnnrkMjhrGnD": "7000",
      "xeGVxN2u4Sp3": "<123456789>",
      "upgseICLHsZe": "<Xwormmm>",
      "jF5pyMR4K1B8": 3,
      "VpYiyt9aVUsv": "USB.exe",
      "z7mwUS4LmaFC": "%AppData%",
      "Fjg9TdM4RTsH": "tBZ7NDtphvUCm0Dc",
      "5BPKEMIKpcCV": "\\Log.tmp"
    }
  },
  {
    "file_path": "dangerzone/vstdlib_s64",
    "sha256": "6e5671dec52db7f64557ba8ef70caf53cf0c782795236b03655623640f9e6a83",
    "yara_possible_family": "quasarrat",
    "key": "526f35346a62726168486530765a6266487a7039685575526637684a737575794b4c7933654e5a3465644c415a71455861676b3078357767563277364d544b5339367279367959664d6a66456f35653934784e396c684e346b514c4e7479317442704974",
    "salt": "None",
    "config": {
      "Version": "1.0.00.r6",
      "RECONNECTDELAY": 5000,
      "PASSWORD": "5EPmsqV4iTCGjx9aY3yYpBWD0IgEJpHNEP75pks",
      "SPECIALFOLDER": "APPLICATIONDATA",
      "SUBFOLDER": "SUB",
      "INSTALLNAME": "INSTALL",
      "INSTALL": false,
      "STARTUP": true,
      "Mutex": "e4d6a6ec-320d-48ee-b6b2-fa24f03760d4",
      "STARTUPKEY": "STARTUP",
      "HIDEFILE": true,
      "ENABLELOGGER": true,
      "Key": "O2CCRlKB5V3AWlrHVKWMrr1GvKqVxXWdcx0l0s6L8fB2mavMqr",
      "Group": "RELEASE",
      "xor_decoded_strings": [
        "BPN - Nuestro Banco",
        "Red Link - bpn",
        "HB Judiciales BPN",
        "Ingresá a tu cuenta",
        "Online Banking Web",
        "Banca Empresa 3.0",
        "Banco Ciudad",
        "Banco Ciudad | Autogestión",
        "Banca Empresa 3.0",
        "Banco Comafi - Online Banking",
        "Banco Comafi - eBanking Empresas",
        "Online Banking Santander | Inicio de Sesión",
        "Online Banking Empresas",
        "Online Banking",
        "Office Banking",
        "HSBC Argentina",
        "HSBC Argentina | Bienvenido",
        "accessbanking.com.ar/RetailHomeBankingWeb/init.do?a=b",
        "ICBC Access Banking | Home Banking",
        "Banco Patagonia",
        "ebankpersonas.bancopatagonia.com.ar/eBanking/usuarios/login.htm",
        "Página del Banco de la Provincia de Buenos Aires",
        "Red Link",
        "bind - finanzas felices :)",
        "BindID Ingreso",
        "BBVA Net Cash | Empresas | BBVA Argentina",
        "Bienvenido a nuestra Banca Online | BBVA Argentina",
        "Ingresá tu e-mail, teléfono o usuario de Mercado Pago",
        "Mercado Pago | De ahora en adelante, hacés más con tu dinero.",
        "Mercado Pago",
        "Home Banking",
        "Office Banking",
        "Banco Santa Cruz Gobierno - Una propuesta para cada Comuna o Municipio | Banco Santa Cruz",
        "Home banking",
        "Office Banking",
        "Banco de Santa Cruz",
        "Red Link",
        "Banco de la Nación Argentina",
        "Red Link - BANCO DE LA NACION ARGENTINA",
        "Red Link",
        "Macro | Agenda powered by Whyline",
        "Banco Macro | Banca Internet Personas",
        "Banco Macro | NUEVA Banca Internet Empresas",
        "https://argentina-e4162-default-rtdb.firebaseio.com/user.json",
        "C:\\\\Users\\\\",
        "\\\\AppData\\\\Local\\\\Aplicativo Itau",
        "C:\\\\Program Files\\\\Topaz OFD\\\\Warsaw",
        "C:\\\\ProgramData\\\\scpbrad",
        "C:\\\\ProgramData\\\\Trusteer",
        "dd.MM.yyyy HH:mm:ss",
        "application/json",
        "Sistema no disponible, intente nuevamente más tarde.",
        "SENHA DE 6 BPN",
        "SENHA DE 6 NB",
        "SENHA DE 6 CIUDAD",
        "SENHA DE 6 COMAFI",
        "SENHA DE 6 GALACIA",
        "SENHA DE 6 HSBC",
        "SENHA DE 6 ICBC",
        "SENHA DE 6 PATAGONIA",
        "SENHA DE 6 PROVINCIA",
        "SENHA DE 6 SANTANDER",
        "SENHA DE 6 BIND",
        "SENHA DE 6 BBVA",
        "driftcar.giize.com:443",
        "adreniz.kozow.com:443"
      ]
    }
  }
]
```

## Feedback, Issues, and Additions

If you have suggestions for improvement, bugs, feedback, or additional RAT families that use a similar configuration format as AsyncRAT, QuasarRAT, VenomRAT, DcRAT, etc. that are not yet supported, please send me a message on [Mastodon](https://infosec.exchange/@jeFF0Falltrades), [YouTube](https://www.youtube.com/c/jeff0falltrades), or submit an Issue or PR in this repo.

Also, if this tool or video tutorial was helpful to you, that's always nice to hear as well!

Thank you!

## Contributions & Attribution
Huge thanks to the following contributors for their outstanding work:

- [doomedraven](https://github.com/doomedraven): For your help in integrating RKP into CAPEv2, as well as your continued contributions to the project as a coauthor
- [cccs-rs](https://github.com/cccs-rs): For your help in integrating RKP into AssemblyLine, as well as helping me wrap it to work with MACO

The logo for this project contains modifications of the following images:

- Ouroboros (modified) - Image by Freepik - https://www.freepik.com/free-vector/ouroboros-symbol-illustration_37368320.htm
- Rat King Illustration (modified) - User:Di (they-them), CC BY 4.0 <https://creativecommons.org/licenses/by/4.0>, via Wikimedia Commons - https://commons.wikimedia.org/wiki/File:Rat_King_Illustration.svg
