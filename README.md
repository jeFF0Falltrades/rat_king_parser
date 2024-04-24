![rat_king_parser logo](https://raw.githubusercontent.com/jeFF0Falltrades/rat_king_parser/master/.github/logo.png)

# Rat King Configuration Parser

A robust, multiprocessing-capable, multi-family RAT config parser/extractor for AsyncRAT, DcRAT, VenomRAT, QuasarRAT, and cloned/derivative RAT families.

This configuration parser seeks to be "robust" in that it does not require the user to know the strain of RAT ahead of time; It simply looks for patterns of a common configuration module that is present in the above-mentioned RAT families (or performs a brute-force search for this config if these patterns are not found) as well as several clones and derivatives, parses and decrypts the config within that module, and uses YARA to suggest a possible strain for the payload.

The initial (non-brute-forcing) method of detection and parsing is detailed in the accompanying YouTube code overview video here:

- https://www.youtube.com/watch?v=yoz44QKe_2o

and based on the original AsyncRAT config parser and tutorial here:

- https://github.com/jeFF0Falltrades/Tutorials/tree/master/asyncrat_config_parser

## Usage

### Installing Requirements

Python requirements can be installed with pip:

```bash
python -m pip install -r requirements.txt
```

YARA must be [installed separately](https://yara.readthedocs.io/en/stable/gettingstarted.html#compiling-and-installing-yara).

### Usage Help

```bash
$ python rat_king_parser.py -h
usage: rat_king_parser.py [-h] [-d] [-r] [-y YARA] file_paths [file_paths ...]

positional arguments:
  file_paths            One or more RAT payload file paths

options:
  -h, --help            show this help message and exit
  -d, --debug           Enable debug logging
  -r, --recompile       Recompile the YARA rule used for family detection prior to running the parser
  -y YARA, --yara YARA  Uses the *compiled* yara rule at this path to determine the potential family of each payload (uses a prepackaged rule at yara_rules/rules.yarc by default)
```

### Using YARA for Payload Identification

A [YARA](https://yara.readthedocs.io/en/latest/) rule for RAT family identification is included with this script in `yara_rules` in both raw and compiled forms.

However, using the `--yara` flag allows a user to specify their own custom YARA rule to use for identification as well.

If you encounter errors using the included compiled YARA rule (which most often occur due to mismatched YARA versions), the included rule can be recompiled using your local YARA version using the `--recompile` flag.

`yara_rules/recompile.py`, which is the module called by the `--recompile` flag, can also be executed on its own to recompile any YARA rule:

```bash
$ python yara_rules/recompile.py -h
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

## Example Input/Output

```bash
$ python rat_king_parser.py ../malz/* | python -m json.tool
```

```json
[
  {
    "file_path": "../malz/quasarrat_obfuscated.exe",
    "sha256": "83892117f96867db66c1e6676822a4c0d6691cde60449ee47457f4cc31410fce",
    "possible_yara_family": "quasarrat",
    "aes_key": "ff230bfb57fecad4bd59d4d97f6883b4",
    "aes_salt": "bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941",
    "config": {
      "\u68bd\u7568\u82be\u21fc\ubc94\u4a16\ua52d\u29ed\u3159\u2884\u71bc\ua7ff\u2f33\u1dcd\u782b\u1878\ua7ff\uffbc\u0d39\ue507": "1.3.0.0",
      "\ua944\uee87\ucc65\u875d\u0fd9\u12f7\u444c\u2b5e\ue0e2\u2fd1\u399d\ueb76\u4712\u4598\u82d8\ua0e7\uc772\u36a5\u1844\u5aac": "qztadmin.duckdns.org:9782;",
      "\u86b9\u562a\ua71f\uc023\uc4e1\u7232\u5284\u3ddf\u8011\uce0b\u03f6\ufffd\u0ae5\u1f42\u4cac\u3eb2\u91fa\u7f71\u606b\u1fd7": 3000,
      "\u59f0\uebd3\ucb55\u9513\u0085\u6ee7\ua940\u681e\u4e2b\uac23\u6a76\u8b4c\u7ab4\u05ee\ua129\uf55c\uf000\u90aa\uf237\u1dfa": "1WvgEMPjdwfqIMeM9MclyQ==",
      "\u03b1\u0425\u0247\u3089\ua076\ua115\u6429\u3006\u1b8d\ubf6d\u2a56\u89ae\u03d5\u9deb\ua766\uac88\u5c44\ub85a\uecbf\uc422": "NcFtjbDOcsw7Evd3coMC0y4koy/SRZGydhNmno81ZOWOvdfg7sv0Cj5ad2ROUfX4QMscAIjYJdjrrs41+qcQwg==",
      "\uf248\ub9fb\u80fc\u41f8\ue537\uef74\ue9e3\ufcca\u34a1\u882f\uce63\u1c36\u21f7\u6549\u8b35\uc644\u702b\u18e3\u7a76\u0c39": "APPLICATIONDATA",
      "\uf0ca\uec38\ub515\u6f29\ub7d9\u8939\ud375\u1b90\u8789\ub5cf\ud75b\u1169\u99d4\uc87e\u695d\ud335\uf8f4\u1ce6\ua50d\ud4e9": "SubDir",
      "\u6964\ucfc4\u3115\u076e\u39b2\uff0f\u2ce1\u00c0\u9619\ue20f\u695e\u5abe\u2be5\u8236\u36bd\u4f95\ub109\u4720\u0d71\u80cd": "Client.exe",
      "\ua9b6\u25ca\ua1d4\u3eba\uf365\u2afa\u9ec6\u22da\u3a7c\ufaef\uc86e\u746d\u7bdb\uc2e7\u791e\uf7cc\u16c2\uf1d7\u5375\u1803": false,
      "\u96d2\ufd5a\ud468\u7e4f\ufffd\u5277\u1b2c\u2d6a\ufffd\uadef\uec19\uc8e5\u7fa2\ua287\u912c\u8b46\ue05c\u5c7f\u9758\u7ee0": false,
      "\ubdc9\u0de2\uf126\u1b1a\u6764\u7fbe\u59e3\u7c7c\u43e4\u5362\uaea2\u9f15\ufffd\uc896\uf7bb\u2cac\ub54c\ubbe9\uabea\uce96": "QSR_MUTEX_YMblzlA3rm38L7nnxQ",
      "\u6500\u3fd8\uc642\u3a4b\u139f\u44ff\u4554\ufffd\u062f\u5dde\ucbf2\ua008\u7ea7\u4007\ufffd\ufd0d\u54da\ua7ae\u5e52\uf347": "Quasar Client Startup",
      "\u4791\u968c\u11c5\uf118\u6b09\u1148\ud085\ufa94\uebf7\u876c\u4782\u9f3f\u286e\ub03e\u925b\ucde1\uea63\u7f61\u8845\uc448": false,
      "\u9db9\u9c76\ua3ed\u00a5\uc4a5\ub160\u2a9a\u3422\ua536\ufffd\u35ec\uc06b\ueb88\ufe70\uae67\ub0c1\u9b98\ue33f\u0c0b\u9133": true,
      "\ub15d\ub9ef\ub130\u9e38\u83a8\ub451\u2918\u3512\u8372\ubf53\u2895\u288f\u5e67\u7682\ud7ab\u1bdd\u4a74\u9d54\u90ab\uaf88": "mDf8ODHd9XwqMsIxpY8F",
      "\uf87d\ufffd\u8363\u06b2\u8698\ue349\u9a0c\u6bbc\u3ad4\uf6d6\u179a\ubce1\u0f2d\u8bef\ud3ae\u9820\u4b21\ufffd\u7872\uc6a3": "Office04",
      "\u13ce\u3b87\u6cc4\uf094\ucbac\u6acc\uee1e\u29a4\ud03c\ub738\uef1c\u59ed\ud00f\u9516\u9413\ue2b0\u8eb2\u7f78\uba47\u3003": "Logs",
      "\u07e2\u8a34\ueb43\ufed8\u7bcb\uaeeb\uc2b4\u3e5e\u18a1\u5c16\u0164\u5cba\u1347\u5eb5\ufffd\u734d\u11d4\u54dc\ufeb2\u66bd": true,
      "\uf855\u7979\uf1a4\ub970\u3aec\ufffd\u4f2b\u8529\u236d\u49c7\u8295\u3d7c\u920d\u4c38\u0437\u4636\u87e8\u5e9b\ucd43\ud110": false
    }
  },
  {
    "file_path": "../malz/asyncrat_blank.exe",
    "sha256": "0e19cefba973323c234322452dfd04e318f14809375090b4f6ab39282f6ba07e",
    "possible_yara_family": "asyncrat",
    "aes_key": "None",
    "aes_salt": "bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941",
    "config": {
      "Ports": "%Ports%",
      "Hosts": "%Hosts%",
      "Version": "%Version%",
      "Install": "%Install%",
      "InstallFolder": "%Folder%",
      "InstallFile": "%File%",
      "Key": "%Key%",
      "MTX": "%MTX%",
      "Certificate": "%Certificate%",
      "Serversignature": "%Serversignature%",
      "Anti": "%Anti%",
      "Pastebin": "%Pastebin%",
      "BDOS": "%BDOS%",
      "Delay": "%Delay%",
      "Group": "%Group%"
    }
  },
  {
    "file_path": "../malz/asyncrat_encrypted.exe",
    "sha256": "6b99acfa5961591c39b3f889cf29970c1dd48ddb0e274f14317940cf279a4412",
    "possible_yara_family": "asyncrat",
    "aes_key": "eebdb6b2b00c2501b7b246442a354c5c3d743346e4cc88896ce68485dd6bbb8f",
    "aes_salt": "bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941",
    "config": {
      "Ports": "2400",
      "Hosts": "minecraftdayzserver.ddns.net",
      "Version": "0.5.8",
      "Install": "true",
      "InstallFolder": "%AppData%",
      "InstallFile": "WinRar.exe",
      "Key": "VUpkMU9UTEhRSEVSN2d2eWpLeDJud2Q0STFIcDRXS0U=",
      "MTX": "LMAsmxp3mz2D",
      "Certificate": "MIIE4DCCAsigAwIBAgIQAM+WaL4OeJIj4I0Usukl1TANBgkqhkiG9w0BAQ0FADARMQ8wDQYDVQQDDAZTZXJ2ZXIwIBcNMjQwNDA0MTYzMzA2WhgPOTk5OTEyMzEyMzU5NTlaMBExDzANBgNVBAMMBlNlcnZlcjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKhz3rO2b0ITSMGvwlS7uWZLVU7cuvYiIyB2WnGxe2SUlT5/pZrRxfX6CVL8t11S5CG3UFMdKDutLiA1amqLDbkqZAjG/g1J+7OPUOBrBWfzpEk/CFCFjmUTlMPwM00DtDp5Ju8ONc09JiaL9Ni3GeYsXza+HZB0WRrgpKnMNu+833ddBOaIgdvB4KicE/S8hSRq5kTNIhiNNZ0nrMFgzaQj0ijyXNTXN7nFCTqRSkWn/2pdveWZLqzTRZ5HsUkeXr2vhSdrrk7KOpHWjqNr2Nhl+bqsIRUhwnthLhj6N1Y94W25j3ATrLR6mjjZTGI2wRm95bMe/7V4DxqV30i6MVrwYMXKcaPO+NHoF9P1lErhCgttEGyWJz2dVJqVCXA+fE8hLyKSUeJSwaBJ36Of/OFGXXMXpUD7eFHNCN2yPVsW1ogS04/xkQUmbWbRjYx/l02+RK/kAK3YsZDuvcLsbKoDq7XJKoBVfvbv5W7jcmMvHHT54PNbmkAUasbtM/+/KhKQe1etOoYd+gOv7tgcNFRVH6N6eSuTxasCYjCr9tSLLmziNalWTknHgBtL/x49BJw6FWwrEE3wsl3C4ALfHQFbtI6sTLdCk7t/oNFUhpVE4kwql5xtOpYpkAj500jGfmVc9Wjy34tON2QLKnzAO87pt8XyANEFQdm3qUJX56KdAgMBAAGjMjAwMB0GA1UdDgQWBBRP67T1n4GPr5zJ0tsXMJ+gL7IawDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4ICAQBMOPQsFZRxqhZZ344n0qBiatzq/jSmfMsMKWYMTiFHHccrgSc63C+nlVpTSCys2BZaMyocxeWKI+w7NklntQhp058+oN7PVC87xod6uZQyfYG1oCR58+Po4I3lWHVdOWQrkEKf4LTpCtyPXPTccZL3AjYcZWLOvP0gcjRsF2dSGnN1WdTPKHxj+OLSwSxlwTW4WN2wg++OV9cmT4wgaT2jPDqv3twxV+JVwEeXMM7XthJsG8ajToCS3Sf7pXnuOBIBoITQEbi7Iyqm/mJwFmAkcpEXb88rHZnKs+rRzjPRI/XsvlGVVuyiHtvPJL9X+R3VVltvrawBCbmN9K2W21E56Nryip0q4wdcF1jJUHXxAiQo/jcu8fO3RGfs9I6SN54PXSWABS7MvNJU8njC1N3J110cnjTgVMNrgRhBHe6r9CGnN4gm9oKvKL5+0/zZvhUPgYusOHIQmdOdfLo0r7tckUk2D18ufRILcaOqyaHLI7Mri1XEli8Brfjdtv/dlpssh/B2/o3bhBlRVD4oL+EX71Bm6cHEKoCLL6zGySSQosQyZpR2j4qVObb5fK1EnilJG4Qk6mNULZfWVPD9TLsJTHEioV8GibykF5O79kruha/pxFvVnoDJHbTPZEWfuR4cb6YIFbTg9pJrOhUsoyZg41leCrcqHR82XOVB755xfw==",
      "Serversignature": "PBjqcvsYypDmnjgUVv1SkvtLx+jFt2V7NyZ+nHik0CWcLbwOwBXD6/3an89d/I7pFAxwZXgSiLunc1yCOocUvymhbMwqT5t/yuj4GdW3a16vZSUuPbvGEOuB2oCgUNrsLWzqshnd1yaTIbNoENLJNS3phGLnQXijbrE2/mSEWbSjLcCWMC7Q52c54RCiBuKPQEhFR1KMUBtSeskObCEqOKY9tYsKKTDYDrQPp32Ho4qArPCDIiefcNiT4k17Dw4srW1OkC3uhSCc7BV1dZA/HJw5gd34pFTeCnJnqY34OmE7sux8mhBjaIXSJMXD81272ngrmGwu6++6DkdLgIx2y3uE6IcUFDQmOgU6T9I0ulogZGGZa1PI3VjBjF4TK27EwzrkR0iKi8Ctn8z/HMXnskviCaui6RlxEzWqOytSfe4m0XHpNN2gHVhKbZwJUr5IwKASOWiXgsOVpkTn8K6PDN22X2rCUigjRsE4/45qhd6BFCa/pXMgCHljHKi5qp13yor91rO9n6NjbO2bP28cexUmUwf03lClGQ2og8q05WWiqHHvLlpHxmy8fZwzniJC3tr6htyPYhGpzo20BMOz/x66tA/+JTC8CFFilvf3PP97KwfqpVNqtnyHVui7QR39E6QvoyNzw+7AxpHCSYx6F9tyWu96pBeSbCrMzXaSV0k=",
      "Anti": "false",
      "Pastebin": "null",
      "BDOS": "false",
      "Delay": "3",
      "Group": "Default"
    }
  },
  {
    "file_path": "../malz/dcrat2.exe",
    "sha256": "034941c1ea1b1ae32a653aab6371f760dfc4fc43db7c7bf07ac10fc9e98c849e",
    "possible_yara_family": "dcrat",
    "aes_key": "3915b12d862a41cce3da2e11ca8cefc26116d0741c23c0748618add80ee31a5c",
    "aes_salt": "4463526174427971777164616e6368756e",
    "config": {
      "Por_ts": "2525",
      "Hos_ts": "20.200.63.2",
      "Ver_sion": " 1.0.7",
      "In_stall": "false",
      "Install_Folder": "%AppData%",
      "Install_File": "",
      "Key": "dU81ekM1S2pQYmVOWWhQcjV4WlJwcWRkSnVYR2tTQ0w=",
      "MTX": "DcRatMutex_qwqdanchun",
      "Certifi_cate": "MIICMDCCAZmgAwIBAgIVANpXtGwt9qBbU/pdFz8d/Pt6kzb7MA0GCSqGSIb3DQEBDQUAMGQxFTATBgNVBAMMDERjUmF0IFNlcnZlcjETMBEGA1UECwwKcXdxZGFuY2h1bjEcMBoGA1UECgwTRGNSYXQgQnkgcXdxZGFuY2h1bjELMAkGA1UEBwwCU0gxCzAJBgNVBAYTAkNOMB4XDTIxMDIxNzA5MjAzM1oXDTMxMTEyNzA5MjAzM1owEDEOMAwGA1UEAwwFRGNSYXQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKt8nE3x/0XYeyDBrDPxdpVH1EMWSVyndAkdVChKaWQFOAAs4r/UeTmw8POG3jUz/XczWBWJt9Vu4Vl0HJN3ZmRIMr75FDGyieel0Vb8sn0hZcABsNr8dbbzfi+eoocVAyZKd79S0mOUinl4PBhldyUJCvanCnguHux8c2F5vnQlAgMBAAGjMjAwMB0GA1UdDgQWBBRjACzYO/EcXaKzlTz8Oq34J5Zq8DAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBACA8urqJU44+IpPcx9i0Q0Eu9+qWMPdZ09y+6YdumC6dun1OHn1I5F03YqYCfCdq0l3XpszJlYYzPnPB4ThOfiKUwJ1HJWS2lgWKfd+CdSWCch0c2dEE1Pao+xyNcNpuphBraHZYc4ojekgeQ8MSdHVo/YCYpmaJbxFWDhFgr3Lh",
      "Server_signa_ture": "c+KGE0Aw1XRgjGe2Kvay1H3VgUgqKRYGit46DnCR6eW/g+kO+H5oRsfBNkVizj0Q862zTXvLkWZ+ON84bmYhBy3o5YQOPaPyAIXha4ByY150rYRXKkzBR47RkTx616bLYUhqO+PqqNOii9THobbo3zAtwjxEoEWr8s0MLGm2AfE=",
      "Paste_bin": "null",
      "BS_OD": "false",
      "De_lay": "1",
      "Group": "16JUNIO-PJOAO",
      "Anti_Process": "false",
      "An_ti": "false"
    }
  },
  {
    "file_path": "../malz/quasarrat.exe",
    "sha256": "a76af3d67a95a22efd83d016c9142b7ac9974068625516de23e77a5ac3dd051b",
    "possible_yara_family": "quasarrat",
    "aes_key": "b30cea630f7fac6c2e066ce7f29e1b4bab548ee95b20ff6aa7387ce14df5dc30",
    "aes_salt": "bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941",
    "config": {
      "\u5bd8\ue8b1\u8902\u4ab3\ue28f\ua5c9\u9297\ufffd\ua748\u954b\u5801\uccda\u71f1\u7314\u754f\u2036\ud518\u34c4\u0bd2\uabfc": "1.4.1",
      "\ubd74\ua2b2\u88b9\uf912\u680a\u6e1c\u9c57\ufffd\u7f1d\ufa03\uad9d\uefae\uede0\u9540\u0199\uead7\u8879\u6442\u4d27\uc296": "10.0.0.61:4782;24.67.68.3:4782;",
      "\uaf32\u50ed\ud35f\ue8c1\u8116\ua100\u61aa\u446a\ub74a\ufffd\u1029\ue028\u87a5\u9c32\u6a2d\u643c\u2535\ufffd\uef1b\uf76e": 3000,
      "\u8f62\u4a09\u6500\u8f63\ua128\ud6e8\u89c5\ubc5b\u31cd\u663a\u704a\u4531\u4a66\u83fc\u4a96\u302a\ube31\ubebd\u19e8\u02f8": "APPLICATIONDATA",
      "\u07ef\uab1b\ube45\u54a8\u874d\ue0e0\ucca0\u790d\ueb38\u5e8c\u7e34\u730f\u810b\u520f\uf143\u7e8b\u8718\u1ab1\u43ec\ub81d": "SubDir",
      "\u1b53\u2db6\u7a71\u05f5\u15fe\u5dbb\ud45e\ue70f\uc163\uf217\uc3f5\ue4e6\uf509\u7212\uc5a2\uee2c\uccf1\u45a8\u4489\u911b": "GloomTool.exe",
      "\u02b9\u175e\uc513\u9240\u1d5d\ub37e\u7a20\u7dd8\u1709\u68f4\u685b\u0a03\ue1ef\ua892\u0f61\u536b\u0354\ubec7\u3be8\u6095": true,
      "\ucef8\ufffd\ud372\ue90d\u611b\u6b37\u53e3\uc3d8\ud442\uc0ca\u02bf\u1477\u82fd\u2449\uc82b\u73dd\u319c\u4a3c\u1d46\u8f98": true,
      "\u5602\u18be\u066a\uffc6\u116d\uee93\u7b71\u51f6\uc63f\ue0f2\u5dbb\ufb61\uf17c\u085b\u0b6d\u1784\u24b7\u5a29\u62a2\u843d": "9fdd3e80-d560-431b-b526-3ebbc1799110",
      "\u9ff4\ufffd\u86bf\u3143\uc7c4\u1f9a\ub115\u86df\u987b\ua045\u3287\u646f\ud08b\u62de\ubee7\u2270\u1e3a\uec69\ub7cc\u8007": "WindowsAV",
      "\ub6ca\u3566\u419d\u1762\u554d\u2999\ue26d\u2649\u66d7\uae3f\ua1a8\u0df6\u5d48\ufffd\u0861\u1386\u6def\u678d\u5cbd\uadcc": true,
      "\u6c44\ub609\u68c0\ud49b\u9e28\u8fdc\u286e\ub4b3\ue333\u5c6e\u4ab9\uffa2\u7b4e\u06b9\u0a27\u8ed8\u765d\ub817\u4809\u6fac": true,
      "\uab42\u38e0\ucdfc\u0a20\u97f7\u1505\ub1b7\u5d18\u59c3\u36f1\ua70a\u8e85\ud489\uf6bb\ua390\u233d\uabff\u3c76\uf888\u2974": "5F91B88C67A9ACF78B2396771B3B6F2B4615CA57",
      "\uc238\uc713\u338a\u6dd8\ua951\u123a\u08d3\u4de2\u34e6\uee25\u6392\u6eb3\u6600\u8b93\ud1fe\u4bea\ud6f2\uee6e\ufffd\u0fc5": "Office04",
      "\ub9d6\u27d1\u15fd\u6565\u60bc\ufffd\ub07b\ub445\u85bf\u4d12\u23af\ufffd\u5766\ucc79\uf138\ud0cf\u7405\u37d8\ueed4\u4e44": "Logs",
      "\u28ff\u5da4\uba02\u3368\u0311\ud328\u719f\u587e\ue088\u40ad\u1abe\ufffd\ubc83\uff49\ufffd\uf39d\u1489\u83dc\uecb4\u08a7": "KQrwmpZSwOF20ZdNZlVJ7YjgErzUf9cophPOCAULRI4gSid7qeSaRL4LhhUXzEq1JuUlkRR7WTjztBsmwCRqORdxEBFwd1fMTsYFf4COj4yN1sbvc5Yb1qvk6IELnzse14eXVS+y1AbwCOGBEa1P6H2C2X2xH6jZRBMPaFsohcV0z20ZzWpdJw+aQZ/SSbMvE1YFN5o37y3MzAW/nErdZyxLA7t9eTsca+RLT8uHgqU0iEd4Mz1iHUWA2gYY+uPzV1I3oU8LHrWhXnXRhutbShZ80KbE+tfr7XLAIwwol00moTd7GaL4vd/ZeOa3z3nmVO2GxIRMWCmiX52l5MutcuR/nAAR1k+W2ScaAoxXzpb6pwOwccooFty0lpRoO6RMT+g1ux+jwKn4RpH1baEAmA6cu8W2l1mr8dwZ3ra094dUKEdITKRKEviworYIRWDS9w2618tVfRhccHNsbIIp5qZMumne0OVE+FK6rjPZM/Q4OR7++1AQUNiavCOsY6/sbxdb+K43x2PrxzJAPoU33qF2fzXaSIEgbmlqkZFdFOhSVHay5F4lmuvHUGRXmhs37quo874DaCA5phI3aCP8VXIFkHyjOJelIR9wlfsdNY5yOoA2POnFt1Y24YzoPZt3Mc/Nqv74z/cE3LXrJHsgivyZV25nqpiCHL704AfoRpo=",
      "\ufaea\u4908\u9188\u6146\uc2d4\u46be\u6a0e\u6405\uccf6\u7a36\uc15c\u5dba\u1927\u670f\u117e\u3e11\uf326\u3f3f\ud664\u56f8": "MIIE9DCCAtygAwIBAgIQAIhqXB+nLwd+VvEk3rjLsTANBgkqhkiG9w0BAQ0FADAbMRkwFwYDVQQDDBBRdWFzYXIgU2VydmVyIENBMCAXDTI0MDQwNTIyNDkxN1oYDzk5OTkxMjMxMjM1OTU5WjAbMRkwFwYDVQQDDBBRdWFzYXIgU2VydmVyIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArk3R4LAyzBp+YXIUqxBNyT/R94en+jU7NTtJGsCG7I6Tp2ZV6mdTOynApeBLs6RvgIpzxPIbjA7HMoQqRxBDKREcRZJCnK3NdMl+8ZMKU4OLBWINwW4fvZRu2spC79MYiIsKOXRDsfCelPs1llHTbD4b4c+PzbpcGA5gI+luZ6+OKajkGbAKdppse5EdPh+KrE6r74nAJiK9PdvfF1H7XwOVpFChxcYZJmZTG8hfrSFQ/0mSi0CobU71vj8fVkhX0EOVSv/KoilBScsXRYbvNY/uEzS+9f0xsYK5AgJQcUYWLthqKSZbo3T1WecBHKynExf8LbFpC42ACyPbZXtAYt1lyBXyLW8TZS65yquhcVio/ZgAG05WGn+TeA6M+CxNkEZNvgd5PDuBkF6X13w3OXGFOL7i4KBJifSMRyJaqp9i6ksAY8epDRHP1WOXDxnQ8ak+4jyPC6WSZFnGV3DT7lZahvkIaNR8OPR8suOoUWk8Jl9Fxx+DBa6RK3Ht96YkPAf8rY84Hjjp4xp1OF6q88W1YaYo9NtPK+5fkf2pFqa+RC7v3RKgsis3/1xYeBZ8expiCdm5hKTRx0tAkG5bLzC6/Em8cHqCR6lmbPuHgA4ijByU6fLD1JdmwqAcjpy9OIdB8L+G7X8kAu5+WUe5BMiIE6EYvJi3Rpg2fz5Nt9UCAwEAAaMyMDAwHQYDVR0OBBYEFI40k9gCti/BlRy3dUVqsbe3OhMxMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggIBAAXYckulFdYnmtdh24egkttF9h/0AD87o9kAnRwJVu3nu12R+FwJgaihvAQZiKQ4kgTkP//ag9E60xwyzEcj00/yZGzjMAAXONZoEyeCxEF5cMjbtmqLWsFkRaHEpWtcczJ2BChEnFDgoGF2I6TOlr7OGoJnzHmz43bY9dkpDJ+tqIZu5AwoMG4WMoNe+by66G2S1AjyVVimIJA7at12EMIUizO0Qov+iBFHSDiVwOZlUxhfu9TNKwIgQdSLHnTaBg03VFHpLZ63Qtmr12LwTEOUyVSnJXEsgZISQ0abMCaped6jwpR7+VlpU4SGfyBU8caFphJafdgVzhmztrTpYMUJE44d50+5ue9us2H2IH+26/+yBbQdffzp1LAFfYgjOE7k8EFjU3ayPaTN7ORtjCyNzhYRvjUCuopb0rWhJsQQRQJzkblrYJ/ocSfNGUQOoJpykyD1QiGboE11xIPheLYetZrRtkmNtFuVeKg9z7AB1ahxEcNGT/MW/wkxUe500cBLVTFeZtsMl7WYB6iUSxboQ8zZ8eWCDS2hYOxKfxfr54p4AW24Y267djKnAfpnMIsgJzjcDxvGGMBlwcrxb0vM0w+9K2R+M17r4bldxnStJj2Wtgal1TBVP1XexZgarfXw3HstKjhbFH6cb4g7ZW4wdCYE5XA6qZL00XpuSy4t",
      "\u6482\u55cc\u0c00\u6e0c\ub0cb\u2739\uc5f3!\ufffd\ue2a4\u6690\uc017\uc09a\u7623\uad2b\ua765\u0d61\u73c1\u4b66\u438d": true,
      "\uab2a\u1e1c\u930c\u29e5\u7430\u951c\u8251\ub2c5\ue36d\uc373\u5b93\u5e42\uc8fa\u499b\ufffd\u1786\u8f36\uef98\u8dc2\u6926": true,
      "\ub27b\ud270\ufffd\u355e\u1622\u7519\u9d96\u7364\uc9d0\u1fde\u52a9\uba41\u1e31\u6312\u8c77\u2adf\u168a\ub8ea\u6141\u6a1f": "",
      "\uebb2\u4c72\uf95a\ufffd\ufffd\ua787\u4955\u9b1b\ufffd\u884c\ufcc4\ue409\u5744\ub527\u981c\ue9ca\ucb25\u79b8\u7ada\u23fa": "",
      "\u5254\u58f4\u661a\ucf1c\ua701\uea1d\u2f73\u5f72\u61d4\u5da5\u9863\u785d\u82b9\u6196\u9e96\uf4a6\u6ee1\u5883\ua878\uf173": true
    }
  },
  {
    "file_path": "../malz/venom64.exe",
    "sha256": "db09db5bdf1dcf6e607936a6abbe5ce91efbbf9ce136efc3bdb45222710792fa",
    "possible_yara_family": "venomrat",
    "aes_key": "11ed70df5ce22de750c6e7496fa5c51985c321d2d9dd463979337af003644f41",
    "aes_salt": "56656e6f6d524154427956656e6f6d",
    "config": {
      "Por_ts": "4449,7772",
      "Hos_ts": "127.0.0.1",
      "Ver_sion": "Venom RAT + HVNC + Stealer + Grabber  v6.0.3",
      "In_stall": "false",
      "Install_Folder": "%AppData%",
      "Install_File": "",
      "Key": "M1NoWkREazBvNTNGUkRlT0s4TjE1QlRRQmx4bW1zd2U=",
      "MTX": "qmhvogiycvwh",
      "Certifi_cate": "MIICOTCCAaKgAwIBAgIVAPyfwFFMs6hxoSr1U5gHJmBruaj1MA0GCSqGSIb3DQEBDQUAMGoxGDAWBgNVBAMMD1Zlbm9tUkFUIFNlcnZlcjETMBEGA1UECwwKcXdxZGFuY2h1bjEfMB0GA1UECgwWVmVub21SQVQgQnkgcXdxZGFuY2h1bjELMAkGA1UEBwwCU0gxCzAJBgNVBAYTAkNOMB4XDTIyMDgxNDA5NDEwOVoXDTMzMDUyMzA5NDEwOVowEzERMA8GA1UEAwwIVmVub21SQVQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJMk9aXYluIabmb8kV7b5XTizjGIK0IH5qWN260bNCSIKNt2zQOLq6jGfh+VvAA/ddzW3TGyxBUMbya8CatcEPCCiU4SEc8xjyE/n8+O0uya4p8g4ooTRIrNFHrRVySKchyTv32rce963WWvmj+qDvwUHHkEY+Dsjf46C40vWLDxAgMBAAGjMjAwMB0GA1UdDgQWBBQsonRhlv8vx7fdxs/nJE8fsLDixjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAAVFFK4iQZ7aqDrUwV6nj3VoXFOcHVo+g9p9ikiXT8DjC2iQioCrN3cN4+w7YOkjPDL+fP3A7v+EI9z1lwEHgAqFPY7tF7sT9JEFtq/+XPM9bgDZnh4o1EWLq7Zdm66whSYsGIPR8wJdtjw6U396lrRHe6ODtIGB/JXyYYIdaVrz",
      "Server_signa_ture": "BW9mNNWdLZ+UgmfSTOot753DE24GfE+H6HYG5yl4IFszdMLpfQXijxVlt3bcz68PrHwYG2R70J+h9EVUXPjNw2GgCH5I8BvOw6Luh09VjE3YrfERSa2NKJ7baO9U9NDhM4HaSUCUvXGbR6J0itLe+2YthV7GXSCEbbmfZI9UYKU=",
      "Paste_bin": "null",
      "BS_OD": "false",
      "Hw_id": 335806464,
      "De_lay": "1",
      "Group": "Default",
      "Anti_Process": "false",
      "An_ti": "false"
    }
  },
  {
    "file_path": "../malz/venomrat.exe",
    "sha256": "9bfed30be017e62e482a8792fb643a0ca4fa22167e4b239cde37b70db241f2c4",
    "possible_yara_family": "venomrat",
    "aes_key": "86cfd98ca989924e7a9439902dc6a72e315da09c11b100c39cd59b9c9372b192",
    "aes_salt": "56656e6f6d524154427956656e6f6d",
    "config": {
      "Por_ts": "4449",
      "Hos_ts": "127.0.0.1",
      "Ver_sion": "Venom RAT + HVNC + Stealer + Grabber  v6.0.3",
      "In_stall": "false",
      "Install_Folder": "%AppData%",
      "Install_File": "speedy",
      "Key": "TzY1S0thald3UGNURmJTYjNSQVdBYlBQR2tTdUFaTTg=",
      "MTX": "ypxcfziuep",
      "Certifi_cate": "MIICNjCCAZ+gAwIBAgIVALWZXeRliC16frxuoSrGsVJO4U2tMA0GCSqGSIb3DQEBDQUAMGcxFTATBgNVBAMMDHNwZWVkeSBkcmVhbTETMBEGA1UECwwKcXdxZGFuY2h1bjEfMB0GA1UECgwWVmVub21SQVQgQnkgcXdxZGFuY2h1bjELMAkGA1UEBwwCU0gxCzAJBgNVBAYTAkNOMB4XDTIzMDYyNjEzNDc0OFoXDTM0MDQwNDEzNDc0OFowEzERMA8GA1UEAwwIVmVub21SQVQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJ2DCquy6CwL8H/T1Wi72pbKLyGQdoXBDSKpGyIfLgX5091jBQYbvFbROqt6FjbN52GSpnmd4N8TnQE6KGqTmmSmaf/nxMSNcV1sjhxm7NTfnP9vo/vnZngCmzVr91S9REqlKCiotdkIYWqbdwkmYTuqSdHaicP7Tf0H8oOYZIc5AgMBAAGjMjAwMB0GA1UdDgQWBBS/OFCWU/dcBWOe+i6ERcFdHDOwITAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAIT79sUZm5Je3T7yc9GS+pgzsgtf8OXakm0DrY41uytJgXzgi2E/bWIBja4DyuAddL0ziDCamqDQuFA1MhFNki/X0uKgu1ArxZeXlwKqpDv7ihWRqWrE3rHYha0ALSP8DN0Asmpc4FGnrfhoeoLYXRo8EqH+6ctIkggM8OiBYSTm",
      "Server_signa_ture": "Sn1WeJuN+Ypb6kUw4QirT1RzbwUEoeSYTmJAIlg0LayMd/VSwAo+0LnnT/g5HFx4QrqaM689CvKqUNfotQb9cPj05dfgrV3SplVDt5twnK6f8nnScqI8trTCmprH1gnOcoKcY8039kFo9dEj+eOiaBF451W181I5fPJd4Uug1bY=",
      "Paste_bin": "null",
      "BS_OD": "false",
      "Hw_id": 335806464,
      "De_lay": "1",
      "Group": "Default",
      "Anti_Process": "false",
      "An_ti": "true"
    }
  }
]
```

## Feedback, Issues, and Additions

If you have suggestions for improvement, bugs, feedback, or additional RAT families that use a similar configuration format as AsyncRAT, QuasarRAT, VenomRAT, DcRAT, etc. that are not yet supported, please send me a message on [Mastodon](https://infosec.exchange/@jeFF0Falltrades), [YouTube](https://www.youtube.com/c/jeff0falltrades), or submit an Issue or PR in this repo.

Also, if this tool or video tutorial was helpful to you, that's always nice to hear as well!

Thank you!

## Logo Attribution

The logo for this project contains modifications of the following images:

- Ouroboros (modified) - Image by Freepik - https://www.freepik.com/free-vector/ouroboros-symbol-illustration_37368320.htm
- Rat King Illustration (modified) - User:Di (they-them), CC BY 4.0 <https://creativecommons.org/licenses/by/4.0>, via Wikimedia Commons - https://commons.wikimedia.org/wiki/File:Rat_King_Illustration.svg
