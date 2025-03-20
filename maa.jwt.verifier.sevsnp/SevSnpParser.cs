// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens;

namespace maa.jwt.verifier.sevsnp
{
    public class SnpAttestationReport
    {
        public uint Version { get; private set; }
        public uint GuestSvn { get; private set; }
        public ulong Policy { get; private set; }
        public byte[] FamilyId { get; private set; } = new byte[16];
        public byte[] ImageId { get; private set; } = new byte[16];
        public uint Vmpl { get; private set; }
        public uint SignatureAlgo { get; private set; }
        public ulong PlatformVersion { get; private set; }
        public ulong PlatformInfo { get; private set; }
        public uint AuthorKeyEn { get; private set; }
        public uint Reserved1 { get; private set; }
        public byte[] ReportData { get; private set; } = new byte[64];
        public byte[] Measurement { get; private set; } = new byte[48];
        public byte[] HostData { get; private set; } = new byte[32];
        public byte[] IdKeyDigest { get; private set; } = new byte[48];
        public byte[] AuthorKeyDigest { get; private set; } = new byte[48];
        public byte[] ReportId { get; private set; } = new byte[32];
        public byte[] ReportIdMa { get; private set; } = new byte[32];
        public ulong ReportedTcb { get; private set; }
        public byte[] Reserved2 { get; private set; } = new byte[24];
        public byte[] ChipId { get; private set; } = new byte[64];
        public byte[] CommittedSvn { get; private set; } = new byte[8];
        public byte[] CommittedVersion { get; private set; } = new byte[8];
        public byte[] LaunchSvn { get; private set; } = new byte[8];
        public byte[] Reserved3 { get; private set; } = new byte[168];
        public byte[] Signature { get; private set; } = new byte[512];

        public static SnpAttestationReport Parse(byte[] data)
        {
            if (data.Length != 0x4A0)
                throw new ArgumentException($"Expected report length of 0x4A0 (1184) bytes, got {data.Length}.");

            var report = new SnpAttestationReport();
            int offset = 0;

            report.Version = BitConverter.ToUInt32(data, offset); offset += 4;
            report.GuestSvn = BitConverter.ToUInt32(data, offset); offset += 4;
            report.Policy = BitConverter.ToUInt64(data, offset); offset += 8;

            Buffer.BlockCopy(data, offset, report.FamilyId, 0, 16); offset += 16;
            Buffer.BlockCopy(data, offset, report.ImageId, 0, 16); offset += 16;

            report.Vmpl = BitConverter.ToUInt32(data, offset); offset += 4;
            report.SignatureAlgo = BitConverter.ToUInt32(data, offset); offset += 4;
            report.PlatformVersion = BitConverter.ToUInt64(data, offset); offset += 8;
            report.PlatformInfo = BitConverter.ToUInt64(data, offset); offset += 8;

            report.AuthorKeyEn = BitConverter.ToUInt32(data, offset); offset += 4;
            report.Reserved1 = BitConverter.ToUInt32(data, offset); offset += 4;

            Buffer.BlockCopy(data, offset, report.ReportData, 0, 64); offset += 64;
            Buffer.BlockCopy(data, offset, report.Measurement, 0, 48); offset += 48;
            Buffer.BlockCopy(data, offset, report.HostData, 0, 32); offset += 32;
            Buffer.BlockCopy(data, offset, report.IdKeyDigest, 0, 48); offset += 48;
            Buffer.BlockCopy(data, offset, report.AuthorKeyDigest, 0, 48); offset += 48;
            Buffer.BlockCopy(data, offset, report.ReportId, 0, 32); offset += 32;
            Buffer.BlockCopy(data, offset, report.ReportIdMa, 0, 32); offset += 32;

            report.ReportedTcb = BitConverter.ToUInt64(data, offset); offset += 8;

            Buffer.BlockCopy(data, offset, report.Reserved2, 0, 24); offset += 24;
            Buffer.BlockCopy(data, offset, report.ChipId, 0, 64); offset += 64;
            Buffer.BlockCopy(data, offset, report.CommittedSvn, 0, 8); offset += 8;
            Buffer.BlockCopy(data, offset, report.CommittedVersion, 0, 8); offset += 8;
            Buffer.BlockCopy(data, offset, report.LaunchSvn, 0, 8); offset += 8;
            Buffer.BlockCopy(data, offset, report.Reserved3, 0, 168); offset += 168;
            Buffer.BlockCopy(data, offset, report.Signature, 0, 512);

            return report;
        }

        public static SnpAttestationReport FromBase64Url(string encoded)
        {
            var bytes = Base64UrlEncoder.DecodeBytes(encoded);
            return Parse(bytes);
        }

        public string GetReportDataHex() => BitConverter.ToString(ReportData).Replace("-", "").ToLowerInvariant();
        public string GetMeasurementHex() => BitConverter.ToString(Measurement).Replace("-", "").ToLowerInvariant();
        public string GetHostDataHex() => BitConverter.ToString(HostData).Replace("-", "").ToLowerInvariant();
        public string GetIdKeyDigestHex() => BitConverter.ToString(IdKeyDigest).Replace("-", "").ToLowerInvariant();

    }
}