// .NET System.Security.Cryptography.MLKem stimulus runner (msn-2026-0001).
// ImportEncapsulationKey + Encapsulate per vector; records backing/runtime
// metadata so verdicts attribute to an identified codebase.
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

var cliArgs = Environment.GetCommandLineArgs();
if (cliArgs.Length != 3)
{
    Console.Error.WriteLine("usage: dotnet_runner <stimuli.tsv> <report.out>");
    return 2;
}

// FIPS 203 Table 3: (ciphertext, shared-secret) sizes per parameter set.
static (int ct, int ss) Sizes(string p) => p switch
{
    "ML-KEM-512" => (768, 32),
    "ML-KEM-768" => (1088, 32),
    "ML-KEM-1024" => (1568, 32),
    _ => (0, 0),
};

using var inStream = new StreamReader(cliArgs[1]);
using var outWriter = new StreamWriter(cliArgs[2]);

string backing = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "CNG"
                : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "OpenSSL"
                : "managed";
outWriter.WriteLine($"META|runtime={Environment.Version}|os={RuntimeInformation.OSDescription}" +
                    $"|arch={RuntimeInformation.ProcessArchitecture}|mlkemSupported={MLKem.IsSupported}|backing={backing}");

string? line;
int total = 0;
while ((line = inStream.ReadLine()) is not null)
{
    var parts = line.Split('|');
    if (parts.Length < 5) continue;
    string family = parts[0], paramSet = parts[1], expected = parts[2], source = parts[3], ekHex = parts[4];

    MLKemAlgorithm? alg = paramSet switch
    {
        "ML-KEM-512" => MLKemAlgorithm.MLKem512,
        "ML-KEM-768" => MLKemAlgorithm.MLKem768,
        "ML-KEM-1024" => MLKemAlgorithm.MLKem1024,
        _ => null,
    };
    if (alg is null || !MLKem.IsSupported) continue;
    total++;

    byte[] ek;
    try { ek = Convert.FromHexString(ekHex); }
    catch { continue; }
    var (ctLen, ssLen) = Sizes(paramSet);

    try
    {
        using var kem = MLKem.ImportEncapsulationKey(alg, ek);
        byte[] ciphertext = new byte[ctLen];
        byte[] sharedSecret = new byte[ssLen];
        kem.Encapsulate(ciphertext, sharedSecret);
        outWriter.WriteLine($"{family}|{paramSet}|{expected}|{source}|import-accepted|encap-accepted");
    }
    catch (ArgumentException ae)
    {
        outWriter.WriteLine($"{family}|{paramSet}|{expected}|{source}|import-rejected|arg-class:{ae.GetType().Name}");
    }
    catch (CryptographicException ce)
    {
        outWriter.WriteLine($"{family}|{paramSet}|{expected}|{source}|import-rejected|crypto-class:{ce.Message}");
    }
}

outWriter.WriteLine($"SUMMARY|total={total}");
Console.WriteLine($"done: {total} vectors -> {cliArgs[2]}");
return 0;
