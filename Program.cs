using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    public class Program
    {
        static void Main(string[] args)
        {
            var documentDbKeyVaultSecretKeyUri = "https://tobiasbdebug.vault.azure.net/secrets/test/ae6dcdbfdf714bc0ac3d00aecab09bd7";

            var kvClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetToken));

            for (var i = 1; i <= 20; i++)
            {
                var sw = Stopwatch.StartNew();
                var secret = kvClient.GetSecretAsync(documentDbKeyVaultSecretKeyUri).Result.Value;
                Console.WriteLine($"\tGetSecret took {sw.ElapsedMilliseconds}ms (total).");
            }
            Console.Read();
        }

        private static async Task<string> GetToken(string authority, string resource, string scope)
        {
            var authenticationContext = new AuthenticationContext(authority, null);
            X509Certificate2 certificate;
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);

            try
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certificateCollection = store.Certificates.Find(X509FindType.FindByThumbprint, "14B38A82998AA3F9C1949EA87162C6E5FE7A04CD", false);

                if (certificateCollection == null || certificateCollection.Count == 0)
                {
                    throw new Exception("Certificate not installed in the store");
                }

                certificate = certificateCollection[0];
            }
            finally
            {
                store.Close();
            }

            var clientAssertionCertificate = new ClientAssertionCertificate("a3d2c18f-b5d6-47bd-bb32-477962f225a6", certificate);

            var sw = Stopwatch.StartNew();
            try
            {
                return authenticationContext.AcquireTokenAsync(resource, clientAssertionCertificate).Result.AccessToken;
            }
            finally
            {
                Console.Write($"AcquireTokenAsync took {sw.ElapsedMilliseconds}ms.");
            }
        }
    }
}
