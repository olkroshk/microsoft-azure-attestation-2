// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace maa.jwt.verifier.sevsnp
{
    public static class PathUtilities
    {
        public static string GetInputFilePathOrDefault(string[] args, string defaultFileName)
        {
            string filePath;

            if (args.Length > 0)
            {
                filePath = args[0];
                Console.WriteLine("Using file provided via command-line argument.");
            }
            else
            {
                Console.WriteLine($"No arguments found. Using default file '{defaultFileName}' from project root.");
                string? projectRoot = Directory.GetParent(AppContext.BaseDirectory)?.Parent?.Parent?.Parent?.FullName
                    ?? throw new DirectoryNotFoundException("Unable to determine project root.");
                filePath = Path.Combine(projectRoot, defaultFileName);
            }

            Console.WriteLine("Resolved File Path: " + Path.GetFullPath(filePath));

            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("File not found.", filePath);
            }

            return filePath;
        }
    }
}
