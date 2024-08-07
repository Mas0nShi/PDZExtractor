# PDZExtractor

> [!WARNING]
> 仅供学习和研究使用，请勿用于非法用途。
> 
> ONLY FOR STUDYING AND RESEARCH PURPOSES, DO NOT USE IT FOR ILLEGAL PURPOSES.


A tool to extract files from PDZ archives.


> [!NOTE]
> PDZ格式是一种电子书文件格式，主要用于超星阅读器（由超星公司推出的一款电子书阅读及下载管理的客户端软件）中的电子书资源。这种格式的特点是能够提供较好的版权保护，并且通常包含了丰富的电子书阅读功能，如书签、标记、资源采集、文字识别等。
> 
> The PDZ file format is a proprietary format used by the SuperStar Reader software. The format is used to store electronic books and other resources. The format is designed to provide good copyright protection and includes features such as bookmarks, annotations, resource collection, and text recognition.

## Structure of PDZ 

The file has a header named `PDZHdr`, it's include file description, file type, version, etc.

the file structure is as follows:

| Offset | Size | Name          | Desc               | value                                             |
| ------ | ---- | ------------- | ------------------ | ------------------------------------------------- |
| 0      | 4    | magic         | magic value        | 0x67647025                                        |
| 0x4    | 4    | type          |                    | 0x0000007A / 0x0000787A / 0x0000667A / 0x00006D7A |
| 0x8    | 4    | version       | PDZ format version | "1.01"                                            |
| 0xC    | 1    | unknown       |                    |                                                   |
| 0xD    | 1    | cipherType    | packet algo        | 1 = tea<br>2 = des<br>3 = unknown<br>4 = blowfish |
| 0xE    | 1    | unknown       |                    |                                                   |
| 0xF    | 1    | bookType      |                    | enum 1 / 2 / 3 / 4 / 5                            |
| 0x10   | 4    | contentSize   | content size       |                                                   |
| 0x14   | 4    | catalogOffset | catalog offset     |                                                   |
| 0x18   | 4    | catalogSize   | catalog size       |                                                   |
| 0x1C   | 0x20 | marker        | packet marker      |                                                   |
| 0x3C   | 0x4  | checksum      | crc32              |                                                   |
| 0x40   | 0x20 | reserved      | reserved field     |                                                   |

and the catalog is a list of files in the archive, it's structure is as follows:

| Offset | Size | Name     |
| ------ | ---- | -------- |
| 0      | 0xC  | filename |
| 0xC    | 0x4  | offset   |
| 0x10   | 0x4  | size     |

- filename: the name of the file (**None-Terminated**)
- offset: the offset of the file in the archive
- size: the size of the file

## Build

```shell
git clone https://github.com/Mas0nShi/PDZExtractor.git
cd PDZExtractor && cmake -S . -B build
cmake --build build
```

## Usage

```shell
PDZExtractor -f <file> -o <output> -k <hddKey>
```

Example:

```shell
PDZExtractor -f test/11387074.pdz -o output -k "-975353757"
```

## License

[Apache License 2.0](LICENSE)

## Dependencies

- [CLI11](https://github.com/CLIUtils/CLI11)
- [tinyxml2](https://github.com/leethomason/tinyxml2)
