// mytool.cpp  — cleaned & fixed

#include <bits/stdc++.h>

// Crypto++ headers
#include <cryptlib.h>
#include <osrng.h>
#include <secblock.h>
#include <files.h>
#include <filters.h>
#include <hex.h>
#include <base64.h>
#include <aes.h>
#include <modes.h>
#include <ccm.h>
#include <gcm.h>
#include <xts.h>

// locale/io
#include <clocale>
#include <cstdio>

#if defined(_WIN32)
// Giảm kéo theo header COM để tránh 'byte' ambiguous
#define WIN32_LEAN_AND_MEAN
// #define NOMINMAX
#include <windows.h>
#include <shellapi.h>
#include <io.h>
#include <fcntl.h>
#endif

using CryptoPP::AAD_CHANNEL;
using CryptoPP::AES;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::CBC_Mode;
using CryptoPP::CCM;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::DEFAULT_CHANNEL;
using CryptoPP::ECB_Mode;
using CryptoPP::GCM;
using CryptoPP::OFB_Mode;
using CryptoPP::SecByteBlock;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::XTS_Mode;

// ----------------- UTF-8 argv (Windows) -----------------
#if defined(_WIN32)
static std::vector<std::string> get_utf8_argv(int& out_argc) {
    int wargc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    std::vector<std::string> av;
    if (!wargv) { out_argc = 0; return av; }

    av.reserve(wargc);
    for (int i = 0; i < wargc; ++i) {
        int need = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, nullptr, 0, nullptr, nullptr);
        if (need <= 0) { av.emplace_back(); continue; }
        std::string s(need - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, s.data(), need - 1, nullptr, nullptr);
        av.emplace_back(std::move(s));
    }
    LocalFree(wargv);
    out_argc = (int)av.size();
    return av;
}
#endif

// ----------------- UTF-8 console -----------------
static void set_utf8_locale() {
#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stdin),  _O_BINARY);
#endif
    std::setlocale(LC_ALL, "");
}

// ----------------- FS utils -----------------
static bool read_file_bin(const std::string &path, std::string &out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss; ss << f.rdbuf();
    out = ss.str();
    return true;
}
static bool write_file_bin(const std::string &path, const std::string &data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(data.data(), (std::streamsize)data.size());
    return true;
}

// ----------------- encode helpers -----------------
static std::string to_hex(const std::string &s) {
    std::string out;
    StringSource((const CryptoPP::byte*)s.data(), s.size(), true,
        new CryptoPP::HexEncoder(new StringSink(out), false));
    return out;
}
static std::string to_hex(const SecByteBlock &b) {
    std::string out;
    StringSource(b, b.size(), true,
        new CryptoPP::HexEncoder(new StringSink(out), false));
    return out;
}
static bool from_hex(const std::string &hex, std::string &out) {
    try {
        StringSource(hex, true, new CryptoPP::HexDecoder(new StringSink(out)));
        return true;
    } catch(...) { return false; }
}
static std::string to_base64(const std::string &s) {
    std::string out;
    StringSource((const CryptoPP::byte*)s.data(), s.size(), true,
        new CryptoPP::Base64Encoder(new StringSink(out), false));
    return out;
}
static bool from_base64(const std::string &b64, std::string &out) {
    try {
        StringSource(b64, true, new CryptoPP::Base64Decoder(new StringSink(out)));
        return true;
    } catch(...) { return false; }
}

// ----------------- tiny JSON helpers -----------------
static std::string json_escape(const std::string &s) {
    std::string out; out.reserve(s.size()+8);
    for (unsigned char c : s) {
        if (c=='\\' || c=='"') { out.push_back('\\'); out.push_back((char)c); }
        else if (c=='\n') out += "\\n";
        else if (c=='\r') out += "\\r";
        else if (c=='\t') out += "\\t";
        else out.push_back((char)c);
    }
    return out;
}
static bool json_get_string(const std::string &js, const std::string &key, std::string &val) {
    std::string pat = "\"" + key + "\"";
    size_t p = js.find(pat); if (p==std::string::npos) return false;
    p = js.find(':', p); if (p==std::string::npos) return false;
    p = js.find('"', p); if (p==std::string::npos) return false;
    size_t q = js.find('"', p+1); if (q==std::string::npos) return false;
    val = js.substr(p+1, q-(p+1));
    // unescape minimal
    std::string out; out.reserve(val.size());
    for (size_t i=0;i<val.size();++i) {
        char c = val[i];
        if (c=='\\' && i+1<val.size()) {
            char n = val[++i];
            if (n=='n') out.push_back('\n');
            else if (n=='r') out.push_back('\r');
            else if (n=='t') out.push_back('\t');
            else out.push_back(n);
        } else out.push_back(c);
    }
    val.swap(out);
    return true;
}

// ----------------- CLI -----------------
struct Args {
    std::string command;      // enc, dec, bench, kat
    std::string in_file;
    std::string text_in;
    std::string out_file;
    std::string key_file;
    std::string key_hex;
    std::string iv_hex;
    std::string nonce_hex;    // alias for AEAD
    std::string mode = "gcm"; // default
    bool aead = false;
    std::string aad_file;
    std::string aad_text;
    std::string encode = "hex"; // hex|base64|raw
    int threads = 1;
    std::string kat_file;
    bool verbose = false;
    bool allow_ecb = false;
    bool allow_reuse = false;
};

static void print_usage() {
    std::cout <<
    "Usage:\n"
    "  mytool <command> [--in INFILE|--text \"...\"] [--out OUTFILE]\n"
    "         [--key KEYFILE|--key-hex HEX] [--iv IV-hex] [--nonce NONCE-hex]\n"
    "         [--mode MODE] [--aead] [--aad file|--aad-text \"...\"]\n"
    "         [--encode hex|base64|raw] [--threads N]\n"
    "         [--kat path/to/vectors.json] [--verbose] [--allow-ecb] [--allow-reuse]\n"
    "\n"
    "Commands:\n"
    "  enc   Encrypt\n"
    "  dec   Decrypt\n"
    "  bench Benchmark preset payload sizes\n"
    "  kat   Run Known Answer Tests from JSON\n";
}

static bool parse_args(int argc, char **argv, Args &a) {
    if (argc < 2) { print_usage(); return false; }
    a.command = argv[1];
    for (int i=2;i<argc;i++) {
        std::string k = argv[i];
        auto need = [&](std::string &dst){
            if (i+1>=argc) { std::cerr<<"Missing value for "<<k<<"\n"; std::exit(1); }
            dst = argv[++i];
        };
        if (k=="--in") need(a.in_file);
        else if (k=="--text") need(a.text_in);
        else if (k=="--out") need(a.out_file);
        else if (k=="--key") need(a.key_file);
        else if (k=="--key-hex") need(a.key_hex);
        else if (k=="--iv") need(a.iv_hex);
        else if (k=="--nonce") need(a.nonce_hex);
        else if (k=="--mode") need(a.mode);
        else if (k=="--aead") a.aead = true;
        else if (k=="--aad") need(a.aad_file);
        else if (k=="--aad-text") need(a.aad_text);
        else if (k=="--encode") need(a.encode);
        else if (k=="--threads") { std::string v; need(v); a.threads = std::stoi(v); }
        else if (k=="--kat") need(a.kat_file);
        else if (k=="--verbose") a.verbose = true;
        else if (k=="--allow-ecb") a.allow_ecb = true;
        else if (k=="--allow-reuse") a.allow_reuse = true;
        else { std::cerr<<"Unknown flag "<<k<<"\n"; return false; }
    }
    return true;
}

// ----------------- key/iv helpers -----------------
static bool load_key(const Args &a, SecByteBlock &key, std::string &key_desc) {
    std::string raw;
    if (!a.key_hex.empty()) {
        if (!from_hex(a.key_hex, raw)) { std::cerr<<"Invalid key hex\n"; return false; }
        key.Assign((const CryptoPP::byte*)raw.data(), raw.size());
        key_desc = "hex(" + to_hex(std::string((const char*)key.data(), key.size())) + ")";
        return true;
    }
    if (!a.key_file.empty()) {
        std::string f;
        if (!read_file_bin(a.key_file, f)) { std::cerr<<"Cannot read key file\n"; return false; }
        if (f.rfind("hex:",0)==0) {
            std::string h = f.substr(4);
            if (!from_hex(h, raw)) { std::cerr<<"Invalid hex in key file\n"; return false; }
        } else raw = f;
        key.Assign((const CryptoPP::byte*)raw.data(), raw.size());
        key_desc = std::string("file(")+a.key_file+")";
        return true;
    }
    size_t ks = 32;
    key = SecByteBlock(ks);
    AutoSeededRandomPool rng; rng.GenerateBlock(key, key.size());
    key_desc = "generated";
    return true;
}

static bool ensure_iv(const std::string &mode, const Args &a, SecByteBlock &iv) {
    std::string hex = a.nonce_hex.empty()? a.iv_hex : a.nonce_hex;
    std::string raw; size_t need = 0;
    if (mode=="ecb") { iv.CleanNew(0); return true; }
    else if (mode=="cbc"||mode=="cfb"||mode=="ofb"||mode=="ctr") need = 16;
    else if (mode=="xts") need = 16;
    else if (mode=="gcm") need = 12;
    else if (mode=="ccm") need = 12;
    else return false;

    if (!hex.empty()) {
        if (!from_hex(hex, raw)) { std::cerr<<"Invalid IV or nonce hex\n"; return false; }
        if (mode=="ccm") {
            if (raw.size()<7 || raw.size()>13) { std::cerr<<"CCM nonce must be 7..13 bytes\n"; return false; }
            iv.Assign((const CryptoPP::byte*)raw.data(), raw.size());
            return true;
        }
        if (raw.size()!=need) { std::cerr<<"IV length must be "<<need<<" bytes for mode "<<mode<<"\n"; return false; }
        iv.Assign((const CryptoPP::byte*)raw.data(), raw.size());
        return true;
    }
    AutoSeededRandomPool rng; iv.CleanNew(need); rng.GenerateBlock(iv, iv.size());
    return true;
}

static bool load_iv_for_decrypt(const std::string &mode, const Args &a,
                                const std::string &sidecar_json_path,
                                SecByteBlock &iv) {
    std::string hex = a.nonce_hex.empty()? a.iv_hex : a.nonce_hex;
    if (!hex.empty()) {
        std::string raw; if (!from_hex(hex, raw)) { std::cerr<<"Invalid IV/nonce hex\n"; return false; }
        iv.Assign((const CryptoPP::byte*)raw.data(), raw.size());
        return true;
    }
    std::string meta;
    if (!sidecar_json_path.empty() && read_file_bin(sidecar_json_path, meta)) {
        std::string ivhex;
        if (json_get_string(meta, "iv", ivhex)) {
            std::string raw; if (!from_hex(ivhex, raw)) { std::cerr<<"Bad iv in json\n"; return false; }
            iv.Assign((const CryptoPP::byte*)raw.data(), raw.size());
            return true;
        }
    }
    std::cerr<<"Missing IV/nonce: provide --nonce or ensure sidecar .json is present\n";
    return false;
}

// ----------------- nonce registry -----------------
static std::string registry_path() { return ".nonce_registry.json"; }
static bool registry_exists(const std::string &key_hex, const std::string &mode, const std::string &iv_hex) {
    std::ifstream f(registry_path()); if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        std::string k,m,i; json_get_string(line,"key",k); json_get_string(line,"mode",m); json_get_string(line,"iv",i);
        if (k==key_hex && m==mode && i==iv_hex) return true;
    }
    return false;
}
static void registry_add(const std::string &key_hex, const std::string &mode, const std::string &iv_hex) {
    std::ofstream f(registry_path(), std::ios::app); if (!f) return;
    f << "{\"key\":\""<<json_escape(key_hex)<<"\",\"mode\":\""<<json_escape(mode)
      <<"\",\"iv\":\""<<json_escape(iv_hex)<<"\"}\n";
}

// ----------------- AEAD helpers -----------------
struct AEADResult { std::string ciphertext; std::string tag; };

template <class ENC>
static AEADResult aead_encrypt(ENC &enc, const std::string &pt, const std::string &aad, size_t tagSize) {
    std::string out;
    AuthenticatedEncryptionFilter aef(enc, new StringSink(out), false, tagSize);
    if (!aad.empty()) { aef.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size()); aef.ChannelMessageEnd(AAD_CHANNEL); }
    aef.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)pt.data(), pt.size());
    aef.ChannelMessageEnd(DEFAULT_CHANNEL);
    AEADResult r;
    r.ciphertext.assign(out.data(), out.size()-tagSize);
    r.tag.assign(out.data()+out.size()-tagSize, tagSize);
    return r;
}

template <class DEC>
static bool aead_decrypt(DEC &dec, const std::string &ct, const std::string &aad, const std::string &tag, std::string &pt_out) {
    AuthenticatedDecryptionFilter daf(dec, nullptr,
        AuthenticatedDecryptionFilter::MAC_AT_BEGIN | AuthenticatedDecryptionFilter::THROW_EXCEPTION,
        tag.size());
    try {
        daf.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)tag.data(), tag.size());
        if (!aad.empty()) daf.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
        daf.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)ct.data(), ct.size());
        daf.ChannelMessageEnd(AAD_CHANNEL);
        daf.ChannelMessageEnd(DEFAULT_CHANNEL);
        if (!daf.GetLastResult()) return false;
        daf.SetRetrievalChannel(DEFAULT_CHANNEL);
        size_t len = daf.MaxRetrievable();
        pt_out.resize(len);
        if (len) daf.Get((CryptoPP::byte*)&pt_out[0], len);
        return true;
    } catch(...) { return false; }
}

// ----------------- sidecar -----------------
static bool write_sidecar(const std::string &data_out_path, const std::string &json_header) {
    std::string path = data_out_path.empty()? std::string("out.bin.json") : data_out_path + ".json";
    return write_file_bin(path, json_header);
}

// ----------------- enc/dec -----------------
static int cmd_enc(const Args &a) {
    std::string pt;
    if (!a.in_file.empty()) {
        if (!read_file_bin(a.in_file, pt)) { std::cerr<<"Cannot read input file\n"; return 2; }
    } else if (!a.text_in.empty()) pt = a.text_in;
    else { std::cerr<<"Provide --in or --text\n"; return 2; }

    std::string lmode = a.mode; for (auto &c: lmode) c = (char)std::tolower((unsigned char)c);
    if (lmode=="ecb") {
        std::cerr<<"WARNING: ECB offers no semantic security\n";
        if (!a.allow_ecb && pt.size() > 16*1024) { std::cerr<<"ECB blocked on payload > 16 KiB. Use --allow-ecb to override\n"; return 3; }
    }

    SecByteBlock key; std::string key_desc;
    if (!load_key(a, key, key_desc)) return 2;
    SecByteBlock iv;
    if (lmode!="ecb") { if (!ensure_iv(lmode, a, iv)) return 2; }

    const size_t tagSize = 16;
    std::string aad;
    if (!a.aad_file.empty()) { if (!read_file_bin(a.aad_file, aad)) { std::cerr<<"Cannot read AAD file\n"; return 2; } }
    if (!a.aad_text.empty()) aad = a.aad_text;

    if (lmode=="ctr"||lmode=="gcm"||lmode=="ccm") {
        std::string khex = to_hex(std::string((const char*)key.data(), key.size()));
        std::string ivhex = to_hex(iv);
        if (registry_exists(khex, lmode, ivhex)) {
            if (!a.allow_reuse) { std::cerr<<"Unsafe IV or nonce reuse detected for mode "<<lmode<<" (use --allow-reuse to override for lab)\n"; return 4; }
            else std::cerr<<"WARNING: nonce reuse for "<<lmode<<" (overridden by --allow-reuse)\n";
        }
    }

    std::string ct, tag;
    try {
        if (lmode=="ecb") {
            ECB_Mode<AES>::Encryption enc; enc.SetKey(key, key.size());
            StringSource(pt, true, new StreamTransformationFilter(enc, new StringSink(ct)));
        } else if (lmode=="cbc") {
            CBC_Mode<AES>::Encryption enc; enc.SetKeyWithIV(key, key.size(), iv);
            StringSource(pt, true, new StreamTransformationFilter(enc, new StringSink(ct)));
        } else if (lmode=="cfb") {
            CFB_Mode<AES>::Encryption enc; enc.SetKeyWithIV(key, key.size(), iv);
            StringSource(pt, true, new StreamTransformationFilter(enc, new StringSink(ct)));
        } else if (lmode=="ofb") {
            OFB_Mode<AES>::Encryption enc; enc.SetKeyWithIV(key, key.size(), iv);
            StringSource(pt, true, new StreamTransformationFilter(enc, new StringSink(ct)));
        } else if (lmode=="ctr") {
            CTR_Mode<AES>::Encryption enc; enc.SetKeyWithIV(key, key.size(), iv);
            StringSource(pt, true, new StreamTransformationFilter(enc, new StringSink(ct)));
        } else if (lmode=="xts") {
            if (key.size()!=32 && key.size()!=64) { std::cerr<<"XTS requires 256 or 512 bit key\n"; return 2; }
            XTS_Mode<AES>::Encryption enc; enc.SetKeyWithIV(key, key.size(), iv);
            StringSource(pt, true, new StreamTransformationFilter(enc, new StringSink(ct)));
        } else if (lmode=="gcm") {
            GCM<AES>::Encryption enc; enc.SetKeyWithIV(key, key.size(), iv, iv.size());
            auto res = aead_encrypt(enc, pt, aad, tagSize); ct.swap(res.ciphertext); tag.swap(res.tag);
        } else if (lmode=="ccm") {
            CCM<AES,16>::Encryption enc; enc.SetKeyWithIV(key, key.size(), iv, iv.size());
            enc.SpecifyDataLengths(aad.size(), pt.size(), 0);
            auto res = aead_encrypt(enc, pt, aad, tagSize); ct.swap(res.ciphertext); tag.swap(res.tag);
        } else { std::cerr<<"Unsupported mode\n"; return 2; }
    } catch (const std::exception& e) { std::cerr<<"Encrypt error: "<<e.what()<<"\n"; return 2; }

    if (!a.out_file.empty()) {
        if (!write_file_bin(a.out_file, ct + ((lmode=="gcm"||lmode=="ccm")? tag:std::string()))) { std::cerr<<"Cannot write output file\n"; return 2; }
        std::string header = "{";
        std::string alg = "AES-";
        if (lmode=="xts") alg += (key.size()==64? "512":"256");
        else alg += (key.size()==32? "256": key.size()==24? "192":"128");
        header += "\"alg\":\""+alg+"-"+std::string(lmode=="gcm"?"GCM": lmode=="ccm"?"CCM": std::string(1,(char)std::toupper(lmode[0]))+lmode.substr(1))+"\"";
        if (lmode!="ecb") header += ",\"iv\":\""+to_hex(iv)+"\"";
        if (!aad.empty()) header += ",\"aad\":\""+to_hex(aad)+"\"";
        if (lmode=="gcm"||lmode=="ccm") header += ",\"tag\":\""+to_hex(tag)+"\"";
        header += "}";
        write_sidecar(a.out_file, header);
    }

    std::string out_s;
    if (a.encode=="hex") out_s = to_hex(ct + ((lmode=="gcm"||lmode=="ccm")? tag:std::string()));
    else if (a.encode=="base64") out_s = to_base64(ct + ((lmode=="gcm"||lmode=="ccm")? tag:std::string()));
    else out_s = ct + ((lmode=="gcm"||lmode=="ccm")? tag:std::string());
    std::cout << out_s << "\n";

    if (lmode=="ctr"||lmode=="gcm"||lmode=="ccm") {
        std::string khex = to_hex(std::string((const char*)key.data(), key.size()));
        std::string ivhex = to_hex(iv);
        registry_add(khex, lmode, ivhex);
    }
    return 0;
}

static int cmd_dec(const Args &a) {
    std::string in;
    if (!a.in_file.empty()) {
        if (!read_file_bin(a.in_file, in)) { std::cerr<<"Cannot read input file\n"; return 2; }
    } else if (!a.text_in.empty()) {
        if (a.encode=="hex") { if (!from_hex(a.text_in, in)) { std::cerr<<"Invalid hex input\n"; return 2; } }
        else if (a.encode=="base64") { if (!from_base64(a.text_in, in)) { std::cerr<<"Invalid base64 input\n"; return 2; } }
        else in = a.text_in;
    } else { std::cerr<<"Provide --in or --text\n"; return 2; }

    SecByteBlock key; std::string key_desc; if (!load_key(a, key, key_desc)) return 2;
    std::string lmode = a.mode; for (auto &c: lmode) c = (char)std::tolower((unsigned char)c);
    SecByteBlock iv; if (lmode!="ecb") { std::string side = a.in_file.empty()? std::string() : a.in_file + ".json"; if (!load_iv_for_decrypt(lmode, a, side, iv)) return 2; }

    std::string aad;
    if (!a.aad_file.empty()) { if (!read_file_bin(a.aad_file, aad)) { std::cerr<<"Cannot read AAD file\n"; return 2; } }
    if (!a.aad_text.empty()) aad = a.aad_text;

    std::string pt, tag;
    try {
        if (lmode=="gcm"||lmode=="ccm") {
            std::string taghex, meta;
            if (!a.in_file.empty() && read_file_bin(a.in_file + ".json", meta)) json_get_string(meta,"tag",taghex);
            if (!taghex.empty()) {
                std::string rawTag; if (!from_hex(taghex, rawTag)) { std::cerr<<"Bad tag in json\n"; return 2; }
                tag.swap(rawTag);
                if (in.size() < tag.size()) { std::cerr<<"Ciphertext too short for AEAD\n"; return 2; }
                in.resize(in.size()-tag.size());
            } else {
                if (in.size() < 16) { std::cerr<<"Ciphertext too short for AEAD tag\n"; return 2; }
                tag.assign(in.data()+in.size()-16, 16);
                in.resize(in.size()-16);
            }
        }

        if (lmode=="ecb") {
            ECB_Mode<AES>::Decryption dec; dec.SetKey(key, key.size());
            StringSource(in, true, new StreamTransformationFilter(dec, new StringSink(pt)));
        } else if (lmode=="cbc") {
            CBC_Mode<AES>::Decryption dec; dec.SetKeyWithIV(key, key.size(), iv);
            StringSource(in, true, new StreamTransformationFilter(dec, new StringSink(pt)));
        } else if (lmode=="cfb") {
            CFB_Mode<AES>::Decryption dec; dec.SetKeyWithIV(key, key.size(), iv);
            StringSource(in, true, new StreamTransformationFilter(dec, new StringSink(pt)));
        } else if (lmode=="ofb") {
            OFB_Mode<AES>::Decryption dec; dec.SetKeyWithIV(key, key.size(), iv);
            StringSource(in, true, new StreamTransformationFilter(dec, new StringSink(pt)));
        } else if (lmode=="ctr") {
            CTR_Mode<AES>::Decryption dec; dec.SetKeyWithIV(key, key.size(), iv);
            StringSource(in, true, new StreamTransformationFilter(dec, new StringSink(pt)));
        } else if (lmode=="xts") {
            XTS_Mode<AES>::Decryption dec; dec.SetKeyWithIV(key, key.size(), iv);
            StringSource(in, true, new StreamTransformationFilter(dec, new StringSink(pt)));
        } else if (lmode=="gcm") {
            GCM<AES>::Decryption dec; dec.SetKeyWithIV(key, key.size(), iv, iv.size());
            if (!aead_decrypt(dec, in, aad, tag, pt)) { std::cerr<<"GCM auth failed\n"; return 5; }
        } else if (lmode=="ccm") {
            CCM<AES,16>::Decryption dec; dec.SetKeyWithIV(key, key.size(), iv, iv.size());
            dec.SpecifyDataLengths(aad.size(), in.size(), 0);
            if (!aead_decrypt(dec, in, aad, tag, pt)) { std::cerr<<"CCM auth failed\n"; return 5; }
        } else { std::cerr<<"Unsupported mode\n"; return 2; }
    } catch (const std::exception& e) { std::cerr<<"Decrypt error: "<<e.what()<<"\n"; return 2; }

    if (!a.out_file.empty()) {
        if (!write_file_bin(a.out_file, pt)) { std::cerr<<"Cannot write output file\n"; return 2; }
        if (a.verbose) std::cerr<<"Wrote plaintext to "<<a.out_file<<" ("<<pt.size()<<" bytes)\n";
        return 0; // không in ra console nếu đã ghi file
    }

    if (a.encode=="hex") std::cout << to_hex(pt) << "\n";
    else if (a.encode=="base64") std::cout << to_base64(pt) << "\n";
    else { std::cout.write(pt.data(), (std::streamsize)pt.size()); std::cout << "\n"; }
    return 0;
}

// ----------------- bench -----------------
static int cmd_bench(const Args &a) {
    using clock = std::chrono::high_resolution_clock;

    // 6 payloads theo đề bài
    const std::vector<size_t> sizes = {1024, 4096, 16384, 262144, 1048576, 8388608};
    const std::vector<std::string> modes = {"ecb","cbc","cfb","ofb","ctr","xts","gcm","ccm"};

    // Tham số benchmark
    const int ROUNDS_PER_BLOCK = 1000;   // 1 block = 1000 vòng
    const int NUM_BLOCKS      = 10;      // lặp block 30–100 lần (ở đây 50)
    const double WARMUP_SEC   = 0.5;     // warm-up ~0.5s

    AutoSeededRandomPool rng;
    SecByteBlock key256(32); rng.GenerateBlock(key256, key256.size());
    SecByteBlock keyXTS(64); rng.GenerateBlock(keyXTS, keyXTS.size());
    SecByteBlock iv16(16);   rng.GenerateBlock(iv16, iv16.size());
    SecByteBlock iv12(12);   rng.GenerateBlock(iv12, iv12.size());

    std::cout << "mode,payload_bytes,enc_ms,dec_ms,throughput_MBps\n";

    for (const auto& mode : modes) {
        for (size_t sz : sizes) {
            // dữ liệu đầu vào
            std::string pt(sz, '\0');
            rng.GenerateBlock(reinterpret_cast<CryptoPP::byte*>(&pt[0]), pt.size());

            // bộ đệm tái sử dụng (ct có thể lớn hơn pt 16 byte với AEAD)
            std::string ct; ct.reserve(sz + 32); ct.clear();
            std::string rt; rt.reserve(sz + 32); rt.clear();

            // chuẩn bị biến mã hoá/giải mã theo mode
            // (Khởi tạo trong vòng lặp để đảm bảo trạng thái chuẩn mỗi round)
            auto encrypt_once = [&](std::string& out) {
                out.clear();
                if (mode == "ecb") {
                    ECB_Mode<AES>::Encryption e; e.SetKey(key256, key256.size());
                    StringSource(pt, true, new StreamTransformationFilter(e, new StringSink(out)));
                } else if (mode == "cbc") {
                    CBC_Mode<AES>::Encryption e; e.SetKeyWithIV(key256, key256.size(), iv16);
                    StringSource(pt, true, new StreamTransformationFilter(e, new StringSink(out)));
                } else if (mode == "cfb") {
                    CFB_Mode<AES>::Encryption e; e.SetKeyWithIV(key256, key256.size(), iv16);
                    StringSource(pt, true, new StreamTransformationFilter(e, new StringSink(out)));
                } else if (mode == "ofb") {
                    OFB_Mode<AES>::Encryption e; e.SetKeyWithIV(key256, key256.size(), iv16);
                    StringSource(pt, true, new StreamTransformationFilter(e, new StringSink(out)));
                } else if (mode == "ctr") {
                    CTR_Mode<AES>::Encryption e; e.SetKeyWithIV(key256, key256.size(), iv16);
                    StringSource(pt, true, new StreamTransformationFilter(e, new StringSink(out)));
                } else if (mode == "xts") {
                    XTS_Mode<AES>::Encryption e; e.SetKeyWithIV(keyXTS, keyXTS.size(), iv16);
                    StringSource(pt, true, new StreamTransformationFilter(e, new StringSink(out)));
                } else if (mode == "gcm") {
                    GCM<AES>::Encryption e; e.SetKeyWithIV(key256, key256.size(), iv12, iv12.size());
                    // ct sẽ là (ciphertext || tag) theo mặc định
                    StringSource(pt, true, new AuthenticatedEncryptionFilter(e, new StringSink(out)));
                } else if (mode == "ccm") {
                    CCM<AES, 16>::Encryption e; e.SetKeyWithIV(key256, key256.size(), iv12, iv12.size());
                    e.SpecifyDataLengths(0, pt.size(), 0);
                    StringSource(pt, true, new AuthenticatedEncryptionFilter(e, new StringSink(out)));
                }
            };

            auto decrypt_once = [&](const std::string& in, std::string& out) {
                out.clear();
                if (mode == "ecb") {
                    ECB_Mode<AES>::Decryption d; d.SetKey(key256, key256.size());
                    StringSource(in, true, new StreamTransformationFilter(d, new StringSink(out)));
                } else if (mode == "cbc") {
                    CBC_Mode<AES>::Decryption d; d.SetKeyWithIV(key256, key256.size(), iv16);
                    StringSource(in, true, new StreamTransformationFilter(d, new StringSink(out)));
                } else if (mode == "cfb") {
                    CFB_Mode<AES>::Decryption d; d.SetKeyWithIV(key256, key256.size(), iv16);
                    StringSource(in, true, new StreamTransformationFilter(d, new StringSink(out)));
                } else if (mode == "ofb") {
                    OFB_Mode<AES>::Decryption d; d.SetKeyWithIV(key256, key256.size(), iv16);
                    StringSource(in, true, new StreamTransformationFilter(d, new StringSink(out)));
                } else if (mode == "ctr") {
                    CTR_Mode<AES>::Decryption d; d.SetKeyWithIV(key256, key256.size(), iv16);
                    StringSource(in, true, new StreamTransformationFilter(d, new StringSink(out)));
                } else if (mode == "xts") {
                    XTS_Mode<AES>::Decryption d; d.SetKeyWithIV(keyXTS, keyXTS.size(), iv16);
                    StringSource(in, true, new StreamTransformationFilter(d, new StringSink(out)));
                } else if (mode == "gcm") {
                    GCM<AES>::Decryption d; d.SetKeyWithIV(key256, key256.size(), iv12, iv12.size());
                    // in đã chứa tag ở cuối, filter mặc định MAC_AT_END sẽ tự kiểm tra
                    StringSource(in, true, new AuthenticatedDecryptionFilter(d, new StringSink(out)));
                } else if (mode == "ccm") {
                    CCM<AES, 16>::Decryption d; d.SetKeyWithIV(key256, key256.size(), iv12, iv12.size());
                    d.SpecifyDataLengths(0, pt.size(), 0);
                    StringSource(in, true, new AuthenticatedDecryptionFilter(d, new StringSink(out)));
                }
            };

            // Warm-up (dùng CTR cho nhẹ nhàng)
            auto warm_start = clock::now();
            while (std::chrono::duration<double>(clock::now() - warm_start).count() < WARMUP_SEC) {
                CTR_Mode<AES>::Encryption e; e.SetKeyWithIV(key256, key256.size(), iv16);
                std::string tmp; tmp.reserve(sz + 32);
                StringSource(pt, true, new StreamTransformationFilter(e, new StringSink(tmp)));
            }

            // Benchmark theo block
            double enc_total_ms = 0.0, dec_total_ms = 0.0;

            // Tạo 1 ct mẫu ban đầu để vòng decrypt dùng đúng kích thước (đặc biệt AEAD)
            encrypt_once(ct);
            decrypt_once(ct, rt);
            if (rt != pt) {
                std::cerr << "Mismatch (initial) mode=" << mode << " size=" << sz << "\n";
                continue;
            }

            for (int b = 0; b < NUM_BLOCKS; ++b) {
                // Encrypt block
                auto t0 = clock::now();
                for (int i = 0; i < ROUNDS_PER_BLOCK; ++i) {
                    encrypt_once(ct);
                }
                auto t1 = clock::now();

                // Decrypt block
                for (int i = 0; i < ROUNDS_PER_BLOCK; ++i) {
                    decrypt_once(ct, rt);
                    // không so sánh mỗi round để tiết kiệm thời gian, đã check đầu block
                }
                auto t2 = clock::now();

                enc_total_ms += std::chrono::duration<double, std::milli>(t1 - t0).count();
                dec_total_ms += std::chrono::duration<double, std::milli>(t2 - t1).count();
            }

            // Trung bình mỗi vòng
            const double enc_ms_per_round = enc_total_ms / (NUM_BLOCKS * ROUNDS_PER_BLOCK);
            const double dec_ms_per_round = dec_total_ms / (NUM_BLOCKS * ROUNDS_PER_BLOCK);
            const double throughput_MBps   = (double)sz / (1024.0 * 1024.0) / (enc_ms_per_round / 1000.0);

            std::cout << mode << "," << sz << ","
                      << enc_ms_per_round << "," << dec_ms_per_round << ","
                      << throughput_MBps << "\n";
        }
    }
    return 0;
}




// ----------------- KAT -----------------
static int cmd_kat(const Args &a) {
    if (a.kat_file.empty()) { std::cerr<<"Provide --kat path/to/vectors.json\n"; return 2; }
    std::string js; if (!read_file_bin(a.kat_file, js)) { std::cerr<<"Cannot read vectors\n"; return 2; }

    std::vector<std::string> items;
    size_t start = 0;
    while (true) {
        size_t p = js.find("}", start); if (p==std::string::npos) break;
        size_t q = js.rfind("{", p); if (q==std::string::npos) break;
        items.push_back(js.substr(q, p-q+1)); start = p+1;
    }

    int passed = 0, total = 0;
    for (auto &it : items) {
        total++;
        std::string mode; if (!json_get_string(it,"mode",mode)) continue;
        std::string keyh, ivh, aadh, pth, cth, tagh;
        json_get_string(it,"key",keyh); json_get_string(it,"iv",ivh);
        json_get_string(it,"aad",aadh); json_get_string(it,"pt",pth);
        json_get_string(it,"ct",cth);   json_get_string(it,"tag",tagh);
        std::string key,iv,aad,pt,ct,tag;
        from_hex(keyh,key); from_hex(ivh,iv); from_hex(aadh,aad);
        from_hex(pth,pt);   from_hex(cth,ct); from_hex(tagh,tag);

        bool ok = false;
        try {
            if (mode=="GCM") {
                GCM<AES>::Encryption enc; enc.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data(), iv.size());
                auto res = aead_encrypt(enc, pt, aad, tag.size()); ok = (res.ciphertext==ct && res.tag==tag);
            } else if (mode=="CCM") {
                CCM<AES,16>::Encryption enc; enc.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data(), iv.size());
                enc.SpecifyDataLengths(aad.size(), pt.size(), 0);
                auto res = aead_encrypt(enc, pt, aad, tag.size()); ok = (res.ciphertext==ct && res.tag==tag);
            } else if (mode=="CTR") {
                CTR_Mode<AES>::Encryption enc; enc.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
                std::string out; StringSource(pt, true, new StreamTransformationFilter(enc, new StringSink(out))); ok = (out==ct);
            } else if (mode=="CBC") {
                CBC_Mode<AES>::Encryption enc; enc.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
                std::string out; StringSource(pt, true, new StreamTransformationFilter(enc, new StringSink(out))); ok = (out==ct);
            } else if (mode=="CFB") {
                CFB_Mode<AES>::Encryption enc; enc.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
                std::string out; StringSource(pt, true, new StreamTransformationFilter(enc, new StringSink(out))); ok = (out==ct);
            } else if (mode=="OFB") {
                OFB_Mode<AES>::Encryption enc; enc.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
                std::string out; StringSource(pt, true, new StreamTransformationFilter(enc, new StringSink(out))); ok = (out==ct);
            } else { ok = false; }
        } catch(...) { ok = false; }

        if (ok) passed++; else std::cerr<<"KAT fail item mode="<<mode<<"\n";
    }
    std::cout<<"KAT "<<passed<<"/"<<total<<" passed\n";
    return (passed==total)? 0 : 6;
}

// ----------------- main -----------------
int main(int argc, char **argv) {
    set_utf8_locale();
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    Args a;

#if defined(_WIN32)
    int argc_u8 = 0;
    auto args_u8 = get_utf8_argv(argc_u8);
    std::vector<char*> argv_u8; argv_u8.reserve(args_u8.size());
    for (auto &s : args_u8) argv_u8.push_back(const_cast<char*>(s.c_str()));
    if (!parse_args(argc_u8, argv_u8.data(), a)) return 1;
#else
    if (!parse_args(argc, argv, a)) return 1;
#endif

    if (a.command=="enc")   return cmd_enc(a);
    if (a.command=="dec")   return cmd_dec(a);
    if (a.command=="bench") return cmd_bench(a);
    if (a.command=="kat")   return cmd_kat(a);

    print_usage();
    return 1;
}

// ./aes.exe enc --mode gcm --in plain.txt --encode base64 --out out.bin
// ./aes.exe dec --mode gcm --in out.bin `  --key-hex [KEY] `  --out pt.txt

//./aes.exe enc --mode gcm --in plain.txt `  --aad-text "hdr" `  --key-hex 6d02a5e8e3e9e1eae81834fecc32030e88a4164c772cea894f317c5a2c746a20 `  --nonce 0f04f4d9db875e9d904ef71f `  --encode base64 --out out.bin
// ./aes.exe dec --mode gcm --in out.bin `  --aad-text "hdr" `  --key-hex 6d02a5e8e3e9e1eae81834fecc32030e88a4164c772cea894f317c5a2c746a20 `  --nonce 0f04f4d9db875e9d904ef71f ` --encode raw --out pt.txt  