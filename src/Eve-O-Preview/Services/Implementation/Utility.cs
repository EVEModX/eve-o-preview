using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.IdentityModel.Tokens.Jwt;

namespace EveOPreview.Services.Implementation {
    public class Utility {
        private static string GetSSOToken(Process _p) {
            string _token = "";
            string wmiQuery = string.Format("select CommandLine from Win32_Process where ProcessID='{0}'", _p.Id);
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmiQuery);
            ManagementObjectCollection retObjectCollection = searcher.Get();
            foreach (ManagementObject retObject in retObjectCollection)
                _token = retObject["CommandLine"].ToString();
            searcher.Dispose();
            retObjectCollection.Dispose();
            string pattern = @"\/ssoToken=(.*?)\s";
            Match m = Regex.Match(_token, pattern);
            if (m.Success) {
                return m.Groups[1].Value;
            } else {
                return "!MATCH_ERROR";
            }
        }

        public static string GetAccountName(Process _p) {
            string _token = GetSSOToken(_p);
            var jwtToken = new JwtSecurityToken(_token);
            string username = jwtToken.Claims.First(c => c.Type == "name").Value;
            return username;
        }
    }
}
