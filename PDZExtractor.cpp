#include <iostream>
#include <cstdint>
#include <cinttypes>
#include <cstring>
#include <filesystem>

// rename filesystem to std::fs
namespace fs = std::filesystem;


#include "CLI/CLI.hpp"
#include "tinyxml2.h"

#include "cipher/md5.hpp"
#include "cipher/blowfish.hpp"
#include "cipher/aes.hpp"

#include "defer.hpp"

//#define PDZ_DEBUG

#ifdef PDZ_DEBUG
#define LOG_D(fmt, ...) printf("[+] " fmt, ##__VA_ARGS__)
#else
#define LOG_D(fmt, ...) do {} while (0)
#endif
#define LOG_W(fmt, ...) printf("[!] " fmt, ##__VA_ARGS__)
#define LOG_I(fmt, ...) printf("[*] " fmt, ##__VA_ARGS__)
#define LOG_F(fmt, ...) do { printf("[x] " fmt, ##__VA_ARGS__); exit(1); } while (0)
#define ASSERT(cond, fmt, ...) do { if (!(cond)) { LOG_F(fmt, ##__VA_ARGS__); } } while (0)

constexpr char CertPrefix[4] = { 'S', 'S', 'C', 'T'};
constexpr char CertSuffix[4] = { 'S', 'S', 'C', 'E'};

typedef enum : uint32_t {
  PDZ_TYPE_z  = 0x7A,
  PDZ_TYPE_zx = 0x787A,
  PDZ_TYPE_zf = 0x667A,
  PDZ_TYPE_zm = 0x6D7A
} PDZType;


typedef struct {
  char magic[4];
  PDZType type;
  char version[4];
  uint8_t unknown1;
  uint8_t cipherType;
  uint8_t unknown3;
  uint8_t contentType;
  uint32_t contentSize;
  uint32_t catalogOffset;
  uint32_t catalogSize;
  char marker[0x20];
  uint32_t checksum;
  char Reserved[0x20];
} PDZHdr;

struct PDZMeta {
  char name[12];
  int offset;
  int size;
};

const char marker_table[] = {
        0x34, 0x2B, 0x52, 0x54, 0x65, 0x36, 0x69, 0x23, 0x72, 0x33,
        0x25, 0x39, 0x43, 0x75, 0x63, 0x76, 0x5E, 0x26, 0x2A, 0x28,
        0x29, 0x5F, 0x62, 0x6E, 0x32, 0x21, 0x79, 0x68, 0x6A, 0x38,
        0x27, 0x7A, 0x49, 0x2E, 0x2F, 0x51, 0x57, 0x45, 0x35, 0x3D,
        0x7E, 0x74, 0x46, 0x6D, 0x6F, 0x70, 0x5B, 0x5D, 0x5C, 0x61,
        0x40, 0x71, 0x77, 0x42, 0x73, 0x67, 0x2C, 0x4F, 0x47, 0x24,
        0x66, 0x6B, 0x6C, 0x3B, 0x30, 0x2D, 0x48, 0x4A, 0x4B, 0x4E,
        0x4D, 0x3C, 0x60, 0x31, 0x44, 0x64, 0x59, 0x55, 0x56, 0x37,
        0x4C, 0x3A, 0x22, 0x5A, 0x58, 0x78, 0x50, 0x7B, 0x7D, 0x7C,
        0x41, 0x53, 0x3E, 0x3F, 0x00
};

const char cert_table[] = {
        0x29, 0x33, 0x23, 0x2A, 0x45, 0x36, 0x69, 0x23, 0x72, 0x33,
        0x25, 0x39, 0x43, 0x75, 0x63, 0x76, 0x5E, 0x26, 0x2A, 0x28,
        0x29, 0x5F, 0x62, 0x6E, 0x32, 0x21, 0x79, 0x68, 0x6A, 0x38,
        0x27, 0x7A, 0x49, 0x2E, 0x2F, 0x51, 0x57, 0x45, 0x35, 0x3D,
        0x7E, 0x74, 0x46, 0x6D, 0x6F, 0x70, 0x5B, 0x5D, 0x5C, 0x61,
        0x40, 0x71, 0x77, 0x42, 0x73, 0x67, 0x2C, 0x4F, 0x47, 0x24,
        0x66, 0x6B, 0x6C, 0x3B, 0x30, 0x2D, 0x48, 0x4A, 0x4B, 0x4E,
        0x4D, 0x3C, 0x60, 0x31, 0x44, 0x64, 0x59, 0x55, 0x56, 0x37,
        0x4C, 0x5F, 0x22, 0x5A, 0x58, 0x78, 0x50, 0x7B, 0x7D, 0x7C,
        0x38, 0x65, 0x3C, 0x5D, 0x00
};

class CStream final {
public:
  explicit CStream(const char* filename) {
    fp_ = fopen(filename, "rb,ccs=UTF-8");
    ASSERT(fp_ != nullptr, "Failed to open file %s\n", filename);
    fseek(fp_, 0, SEEK_END);
    size_ = ftell(fp_);
    fseek(fp_, 0, SEEK_SET);
    offset_ = 0;
  }

  ~CStream() {
    if (fp_ != nullptr) {
      fclose(fp_);
    }
  }

  template<typename T>
  T read() {
    T val;
    read(&val, sizeof(T));
    return val;
  }

  template<typename T>
  std::unique_ptr<T> read(size_t off) {
    std::unique_ptr<T> val = std::make_unique<T>();
    read(val.get(), off, sizeof(T));
    return val;
  }

  void read(void *buffer, size_t sz) {
    size_t nmemb;
    nmemb = fread(buffer, 1, sz, fp_);
    ASSERT(nmemb == sz, "Failed to read %" PRId64 " bytes\n", sz);
    offset_ += sz;
  }

  void read(void *buffer, size_t off, size_t sz) {
    size_t nmemb, cur;
    cur = ftell(fp_);
    fseek(fp_, (long)off, SEEK_SET);
    nmemb = fread(buffer, sz, 1, fp_);
    ASSERT(nmemb == 1, "Failed to read %" PRId64 " bytes\n", sz);
    fseek(fp_, (long)cur, SEEK_SET);
  }


  void seek(long pos) {
    fseek(fp_, pos, SEEK_SET);
    offset_ = pos;
  }

  [[nodiscard]] size_t size() const {
    return size_;
  }

private:
  FILE *fp_;
  size_t size_;
  size_t offset_;
};


void gen_key_from_cert(char* data, const char* sbox, char* key) {
  char buf[0x80];

  memset(buf, 0, sizeof(buf));

  for (int i = 0; i < strlen(data); i++) {
    buf[i * 2] = data[i];
    buf[i * 2 + 1] = cert_table[i * sbox[i % 4] % 0x60];
  }

  const size_t buf_len = strlen(buf);
  if (buf_len < 0x20) {
    for (size_t i = 0; i < 0x20 - buf_len; i++) {
      buf[buf_len+i] = marker_table[i];
    }
  }

  for (int i = 0; i < 0x20; i++) {
    sprintf(key + i * 2, "%02X", buf[i]);
  }
}

void GetKey(const char* tbl, const char* data, size_t size, const char box[4], char key[0x40]) {
  static const char hex[] = "0123456789ABCDEF";
  auto buf = (char *) malloc(size * 2 + 0x20);
  defer { free(buf); };
  memset(buf, 0, size*2+0x20);

  char tmp[2];
  memset(tmp, 0, sizeof(tmp));
  for (int i = 0; i < size; i++) {
    tmp[0] = data[i];
    strcat(buf, tmp);
    tmp[0] = tbl[i * box[i % 4] % 0x60];
    strcat(buf, tmp);
  }

  const size_t buf_len = strlen(buf);
  if (buf_len < 0x20) {
    for (size_t i = 0; i < 0x20 - buf_len; i++) {
      buf[buf_len+i] = tbl[i];
    }
  }

  for (int i = 0; i < 0x20; i++) {
    key[i * 2] = hex[(buf[i] >> 4) & 0xF];
    key[i * 2 + 1] = hex[buf[i] & 0xF];
  }
}

void tea_decipher(uint32_t* v, uint32_t size, const uint32_t key[4])
{
  uint32_t delta=0x9E3779B9, sum;
  uint32_t v0, v1, v2, v3;
  uint32_t k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3];
  for (int r = 0; r < size / 16; r++) {
    sum = delta * 16;

    v0 = v[r*4+0]; v1 = v[r*4+1]; v2 = v[r*4+2]; v3 = v[r*4+3];

    for (int i=0; i < 16; i++)
    {
      v3 -= (v0 + sum) ^ (k2 + (v0<<4)) ^ (k1 + (v0 >> 5));
      v2 -= (v3 + sum) ^ (k0 + (v3<<4)) ^ (k3 + (v3 >> 5));

      v1 -= (v2 + sum) ^ (k2 + (v2<<4)) ^ (k3 + (v2 >> 5));
      v0 -= (v1 + sum) ^ (k0 + (v1<<4)) ^ (k1 + (v1 >> 5));
      sum -= delta;
    }

    v[r*4+0]=v0; v[r*4+1]=v1; v[r*4+2]=v2; v[r*4+3]=v3;
  }
}

char blowfish_decipher(uint32_t *data, uint32_t size, uint32_t *key) {
  BLOWFISH_CTX ctx;

  Blowfish_Init(&ctx, (uint8_t *) key, 16);

  for (uint32_t i = 0; i < size / 8; i++) {
    uint32_t xl = data[i*2];
    uint32_t xr = data[i*2+1];
    Blowfish_Decrypt(&ctx, &xl, &xr);
    data[i*2] = xl;
    data[i*2+1] = xr;
  }

  return 1;
}

void decrypt_file(void *data, size_t dataSize, int cipherType, const char *key, size_t keySize) {
  uint32_t tmpKey[4];
  uint32_t hash[4];

  md5((uint8_t *) key, keySize, (uint8_t *) hash);
  tmpKey[0] = hash[0] ^ (hash[0] ^ ~hash[0]) & 0x820208;
  tmpKey[1] = hash[1] ^ (hash[1] ^ ~hash[1]) & 0x1220208;
  tmpKey[2] = hash[2] ^ (hash[2] ^ ~hash[2]) & 0x805038;
  tmpKey[3] = hash[3] ^ (hash[3] ^ ~hash[3]) & 0x920208;

  switch (cipherType) {
    case 1:
      tea_decipher(reinterpret_cast<uint32_t *>(data), dataSize, tmpKey);
      break;
    case 4:
      blowfish_decipher(reinterpret_cast<uint32_t *>(data), dataSize, tmpKey);
      break;
    case 2:
    case 3:
    default:
      LOG_F("Unknown cipher type: %d\n", cipherType);
  }
}

int genCertKey(int type, const char* unknown1, const char* hddKey, const char* unknown2, char* key) {
  static const char sk[] = "^*?&";
  LOG_W("Dangerous call named `genCertKey` (this tips means this function may include dangerous operations)\n");
#define NOT_IMPLEMENTED() LOG_F("Not implemented\n")
  switch (type) {
    case 1:
      NOT_IMPLEMENTED();
      GetKey(cert_table, unknown1, strlen(unknown1), sk, key);
      break;
    case 2:
      GetKey(cert_table, hddKey, strlen(hddKey), sk, key);
      break;
    case 3:
      NOT_IMPLEMENTED();
      GetKey(cert_table, unknown2, strlen(unknown2), sk, key);
      break;
    case 4:
    case 5:
      break; // do nothing
    default:
      strcpy(key, "*s{P2a_1mP^?");
  }
  return 1;
}

int GetParam(const char* data, const char* key, void* val, size_t size) {
  LOG_W("Dangerous call named `GetParam` (this tips means this function may include dangerous operations)\n");
  char* params = const_cast<char *>(strstr(data, key));
  if (params == nullptr) return -1;
  params += strlen(key);
  char* end;
  for (end = params; *end != '&' && *end != 0 && *end != ']'; end++);
  if (val == nullptr) goto RTN;
  ASSERT(size >= end - params, "Buffer too small\n");
  memcpy(val, params, end - params);
  RTN:
  return (int)(end - params);
}

size_t BytesFromHex(const uint8_t* hex, const size_t size, uint8_t* bin) {
  char buf[3];

  ASSERT(size % 2 == 0, "Invalid hex string\n");
  memset(buf, 0, sizeof(buf));

  for (int i = 0; i < size / 2; i++) {
    memcpy(buf, hex + i * 2, 2);
    bin[i] = strtol(buf, nullptr, 16);
  }
  return size / 2;
}

void extract_file(CStream& stream, const PDZMeta& meta, const char* bookkey, const int cipherType, fs::path& out) {
  const auto data = (char *) malloc(meta.size);
  defer { free(data); };

  stream.read(data, meta.offset, meta.size);

  // @note: meta.xml is not encrypted
  if (strncmp(meta.name, "meta.xml", 8) != 0) {
    size_t dataSize = meta.size >= 1024 ? 1024 : meta.size;
    decrypt_file(data, dataSize, cipherType, bookkey, strlen(bookkey));
  }

  const auto nameNull = (char *) malloc(sizeof(meta.name) + 1);
  defer { free(nameNull); };
  memcpy(nameNull, meta.name, sizeof(meta.name));
  nameNull[sizeof(meta.name)] = 0;

  const auto outPath = fs::absolute(out / nameNull);

  FILE* fp = fopen(reinterpret_cast<const char *>(outPath.string().c_str()), "wb");
  ASSERT(fp != nullptr, "Failed to open file %s\n", outPath.string().c_str());

  fwrite(data, 1, meta.size, fp);
  fclose(fp);
}


// todo: unknown params
constexpr char unknown1[] = "-1163005939";
constexpr char unknown2[] = "AAAAAAAAAA";

int main(int argc, char** argv) {
  CLI::App app{"PDZ Extractor"};
  argv = app.ensure_utf8(argv);

  fs::path filename;
  fs::path outdir;
  std::string hddKey;
  app.add_option("-f,--file", filename, "PDZ file path")->required()->check(CLI::ExistingFile);
  app.add_option("-o,--outdir", outdir, "Output directory")->required();
  app.add_option("-k,--hddkey", hddKey, "HDD key")->required();

  CLI11_PARSE(app, argc, argv);

  CStream stream(filename.string().c_str());
  // read header
  auto hdr = stream.read<PDZHdr>(0);
  ASSERT(strncmp(hdr->magic, "%pdg", 4) == 0, "Invalid magic\n");

  LOG_D("type: %#" PRIx32 "\n", hdr->type);
  LOG_D("version: '%.4s'\n", hdr->version);
  LOG_D("unknown1: %#" PRIx32 "\n", hdr->unknown1);
  LOG_D("cipherType: %#" PRIx32 "\n", hdr->cipherType);
  LOG_D("contentType: %#" PRIx32 "\n", hdr->contentType);
  LOG_D("contentSize: %#" PRIx32 "\n", hdr->contentSize);
  LOG_D("catalogOffset: %#" PRIx32 "\n", hdr->catalogOffset);
  LOG_D("catalogSize: %#" PRIx32 "\n", hdr->catalogSize);
  LOG_D("marker: '%s'\n", hdr->marker);
  LOG_D("checksum: %#" PRIx32 "\n", hdr->checksum);

  // decrypt catalog and read metadata
  ASSERT(hdr->catalogSize % sizeof(PDZMeta) == 0, "Invalid catalog size\n");
  const auto catalog = (PDZMeta *) malloc(hdr->catalogSize);
  defer { free(catalog); };
  stream.read(catalog, hdr->catalogOffset, hdr->catalogSize);

  const auto catalog_key = (char *) malloc(0x40);
  defer { free(catalog_key); };
  GetKey(marker_table, hdr->marker, sizeof(hdr->marker), "ljhd", catalog_key);
  LOG_D("catalog key: %.64s\n", catalog_key);

  decrypt_file(catalog, hdr->catalogSize, 1, catalog_key, 0x40);

  for (int i = 0; i < hdr->catalogSize / sizeof(PDZMeta); i++) {
    LOG_D("name='%.11s', offset=%#" PRIx32 ", size=%#" PRIx32 "\n", catalog[i].name, catalog[i].offset, catalog[i].size);
  }

  // decrypt cert to get bookkey
  const auto certOff = hdr->contentSize + sizeof(PDZHdr);
  const auto certSize = stream.size() - certOff;

  const auto cert = (char *) malloc(certSize);
  defer { free(cert); };
  stream.read(cert, certOff, certSize);

  ASSERT(strncmp(cert, CertPrefix, 4) == 0, "Invalid cert prefix\n");
  ASSERT(strncmp(cert + certSize - 4, CertSuffix, 4) == 0, "Invalid cert suffix\n");

  // split cert
  const auto sscp = strstr(cert, "[p?");
  ASSERT(sscp != nullptr, "can not found params in cert\n");

  const auto ssch = sscp - 0x20;

  const auto certHashStr = (char *) malloc(0x20);
  defer { free(certHashStr); };

  memcpy(certHashStr, ssch, 0x20);
  LOG_D("certHashStr: %.32s\n", certHashStr);

  const auto ssce = strstr(sscp, "]");
  ASSERT(ssce != nullptr, "can not found end of params in cert\n");

  //  - parse params {key}={value}&...
  // - get unit[int] (optional)
  int unit;
  GetParam(sscp, "unit=", &unit, sizeof(unit));
  unit = atoi(reinterpret_cast<char*>(&unit));
  LOG_D("unit: %#" PRIx32 "\n", unit);

  // - get type[int]
  int type;
  GetParam(sscp, "type=", &type, sizeof(type));
  type = atoi(reinterpret_cast<char*>(&type));
  LOG_D("type: %#" PRIx32 "\n", type);

  // - get un[string]
  const auto unSize = GetParam(sscp, "un=", nullptr, 0);
  const auto un = (char *) malloc(unSize + 1);
  defer { free(un); };
  GetParam(sscp, "un=", un, unSize);
  un[unSize] = 0;
  LOG_D("un: '%s'\n", un);

  // - use certHash to verify cert
  const auto certHashSalt = (char *) malloc(0x40);
  defer { free(certHashSalt); };
  ASSERT(genCertKey(type, unknown1, hddKey.c_str(), unknown2, certHashSalt), "Failed to generate cert hash salt\n");
  LOG_D("certHashSalt: %.64s\n", certHashSalt);

  const auto certBodySize = ssch - cert - sizeof(CertPrefix);
  uint8_t tmpHash[0x10];
  const auto tmpMd5Buf = (char *) malloc(certBodySize + 0x40 + 1);
  defer { free(tmpMd5Buf); };
  sprintf(tmpMd5Buf, "%.*s%.64s", certBodySize, cert + sizeof(CertPrefix), certHashSalt);
  md5(reinterpret_cast<const uint8_t *>(tmpMd5Buf), certBodySize + 0x40, tmpHash);
  // -- compare certHash with tmpHash
  uint8_t certHash[0x10];
  ASSERT(BytesFromHex(reinterpret_cast<const uint8_t *>(certHashStr), 0x20, certHash) == 0x10, "Invalid cert hash\n");
  ASSERT(memcmp(certHash, tmpHash, sizeof(tmpHash)) == 0, "Invalid cert hash\n");

  LOG_I("certHash: %.32s - PASS\n", certHashStr);

  // - get cert body[-4:-1]
  const auto sscb = ssch - 6;
  const auto certBox = (char *) malloc(4);
  defer { free(certBox); };
  memcpy(certBox, sscb, 4);
  LOG_D("certBox: %.4s\n", certBox);


  const auto certBodyAndIv = (char *) malloc(certBodySize - 4); // exclude certBox
  defer { free(certBodyAndIv); };
  memcpy(certBodyAndIv, cert + sizeof(CertPrefix), certBodySize - 6);
  memcpy(certBodyAndIv + certBodySize - 6, cert + sizeof(CertPrefix) + certBodySize - 2, 2);
  LOG_D("certBody: '%.*s'\n", (int)(certBodySize - 4), certBodyAndIv);

  // - get decrypt iv
  const auto certIVHex = (char *) malloc(0x20);
  defer { free(certIVHex); };
  memcpy(certIVHex, certBodyAndIv + certBodySize - 4 - 0x20, 0x20);
  LOG_D("certIV: %.32s\n", certIVHex);

  uint8_t certIV[0x10];
  ASSERT(BytesFromHex(reinterpret_cast<const uint8_t *>(certIVHex), 0x20, certIV) == 0x10, "Invalid to convert cert iv\n");

  // - get decrypt body
  const auto certEncXmlSize = certBodySize - 4 - 0x20;
  const auto certXmlData = (char *) malloc(certEncXmlSize / 2);
  defer { free(certXmlData); };
  BytesFromHex(reinterpret_cast<const uint8_t *>(certBodyAndIv), certEncXmlSize, reinterpret_cast<uint8_t *>(certXmlData));

  // - get aes key
  const auto certKeyHex = (char *) malloc(0x40);
  defer { free(certKeyHex); };
  GetKey(marker_table, certHashSalt, 0x40, certBox, certKeyHex);
  LOG_D("certKey: %.64s\n", certKeyHex);

  uint8_t certKey[0x20];
  BytesFromHex(reinterpret_cast<const uint8_t *>(certKeyHex), 0x40, reinterpret_cast<uint8_t *>(certKey));

  // - decrypt cert body

  AES_ctx ctx;
  AES_init_ctx_iv(&ctx, certKey, reinterpret_cast<const uint8_t *>(certIV));
  AES_CBC_decrypt_buffer(&ctx, reinterpret_cast<uint8_t *>(certXmlData), certEncXmlSize / 2);

  // -- unpad pkcs7
  const auto pad = certXmlData[certEncXmlSize / 2 - 1];
  ASSERT(pad < 0x10 && pad > 0, "Invalid pad\n");
  auto certXmlSize = certEncXmlSize / 2 - pad;
  LOG_I("certXmlData: '%.*s'\n", (int)certXmlSize, certXmlData);

  // - parse xml to get bookkey
  auto certXmlNull = (char *) malloc(certXmlSize + 1);
  defer { free(certXmlNull); };
  memcpy(certXmlNull, certXmlData, certXmlSize);
  certXmlNull[certXmlSize] = 0;

  // - parse xml
  tinyxml2::XMLDocument doc;
  tinyxml2::XMLError err = doc.Parse(certXmlNull);
  ASSERT(err == tinyxml2::XML_SUCCESS, "Failed to parse xml: %s\n", tinyxml2::XMLDocument::ErrorIDToName(err));

  const auto root = doc.FirstChildElement("cert");
  ASSERT(root != nullptr, "Failed to get root element\n");

  const auto certexpdate = root->FirstChildElement("certexpdate");
  ASSERT(certexpdate != nullptr, "Failed to get certexpdate element\n");

  const auto userinfo = root->FirstChildElement("userinfo");
  ASSERT(userinfo != nullptr, "Failed to get userinfo element\n");

  const auto username = userinfo->FirstChildElement("username");
  ASSERT(username != nullptr, "Failed to get username element\n");

  const auto useraccount = userinfo->FirstChildElement("useraccount");
  ASSERT(useraccount != nullptr, "Failed to get useraccount element\n");

  const auto password = userinfo->FirstChildElement("password");
  ASSERT(password != nullptr, "Failed to get password element\n");

  const auto userexpdate = userinfo->FirstChildElement("userexpdate");
  ASSERT(userexpdate != nullptr, "Failed to get userexpdate element\n");

  // ---
  const auto rightinfo = root->FirstChildElement("rightinfo");
  ASSERT(rightinfo != nullptr, "Failed to get rightinfo element\n");

  tinyxml2::XMLElement* bookKey = nullptr;
  if (unit == 1) {
    bookKey = rightinfo->FirstChildElement("key");
  } else {
    bookKey = rightinfo->FirstChildElement("bookkey");
  }
  ASSERT(bookKey != nullptr, "Failed to get bookkey element\n");

  const auto print = rightinfo->FirstChildElement("print");
  ASSERT(print != nullptr, "Failed to get print element\n");

  const auto copy = rightinfo->FirstChildElement("copy");
  ASSERT(copy != nullptr, "Failed to get copy element\n");

  const auto auth = root->FirstChildElement("auth");
  ASSERT(auth != nullptr, "Failed to get auth element\n");

  const auto reserve = root->FirstChildElement("reserve");
  ASSERT(reserve != nullptr, "Failed to get reserve element\n");

  // - get bookkey
  const auto bookKeyStr = bookKey->GetText();
  ASSERT(bookKeyStr != nullptr, "Failed to get bookKey text\n");

  LOG_D("bookKey: '%s'\n", bookKeyStr);

  // - decrypt content
  if (fs::exists(outdir)) {
    fs::remove_all(outdir);
  }
  fs::create_directories(outdir);

  for (int i = 0; i < hdr->catalogSize / sizeof(PDZMeta); i++) {
    extract_file(stream, catalog[i], bookKeyStr, hdr->cipherType, outdir);
    LOG_I("Extracted: %.12s\n", catalog[i].name);
  }

  return 0;
}
