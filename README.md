# reducebin
Remove junk bytes from a large binary malware.

Reducing the size of the malware sample makes it easier to analyze or submit to online sandboxes.

*This script is a first test version, it was written quickly to reduce the size of some malware samples I needed to analyze.*

## How it works
- Convert binary file to Hex string
- Check for blocks of Hex that are 512 characters long
- They are usually hexadecimal with `CC` or `00` values
- Calculate the occurrences and choose the largest one
- Remove all occurrences to reduce file size

## Example

A malware sample whose size is approximately 650MB.

```bash
$ ls -lh malware.exe 
-rw-rw-r-- 1 guelfoweb guelfoweb 647M lug 13 10:33 malware.exe
```

In case null bytes `00` are added at the end of the malware, we can lighten the file by removing the null bytes with the `sed` command:

```bash
sed '$ s/\x00*$//' file.exe > file.exe.bin
```
However, in this case there are no null bytes but a series of hexadecimal "CC", they are not arranged consecutively in a single block but randomly interrupted. 
We can't use the "sed" command like above because we don't know the exact points of the breaks.

```bash
$ xxd malware.exe | tail
286bb850: cccc cccc cccc cccc cccc cccc cccc cccc  ................
286bb860: cccc cccc cccc cccc cccc cccc cccc cccc  ................
286bb870: cccc cccc cccc cccc cccc cccc cccc cccc  ................
286bb880: cccc cccc cccc cccc cccc cccc cccc cccc  ................
286bb890: cccc cccc cccc cccc cccc cccc cccc cccc  ................
286bb8a0: cccc cccc cccc cccc cccc cccc cccc cccc  ................
286bb8b0: cccc cccc cccc cccc cccc cccc cccc cccc  ................
286bb8c0: cccc cccc cccc cccc cccc cccc cccc cccc  ................
286bb8d0: cccc cccc cccc 986b c606 cccc cccc cccc  .......k........
286bb8e0: cccc 608a b206 cccc cccc cccc cccc c802  ..`.............
```

The entropy is quite low, a lower entropy value indicates low randomness in the data.

```bash
$ python3 reducebin.py malware.exe --entropy
The entropy of the file is: 0.03
```
So it is still possible to detect a large enough sequence of hexadecimal code (for convenience we start from a length of 512, but we can calibrate the length using the `--len` parameter) and rely on the number of occurrences (1321814 were detected).

```bash
$ python3 reducebin.py malware.exe
INPUT      : malware.exe
Size       : 646.73 MB
Hash MD5   : AECA52204028884A7EC8DF154F83ACAA
String HEX : CCCCCCCC...CCCCCCCC (length = 512)
Count      : 1321814 (occurrences)

OUTPUT     : malware.exe.reduced
Size       : 1.13 MB
Hash MD5   : 753B5FBABAC18F1A2656FF18CE678C60

Reduction  : 99.83 %
Time       : 00:00:11
```

The resulting file ([rhadamanthys](https://tria.ge/230808-rx1t7ada88)) weighs 1.13 MB, a reduction of 99.83% was achieved.
