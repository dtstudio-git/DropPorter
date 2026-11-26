using System.Diagnostics;
using System.IO;

namespace DropPorter.Wpf;

internal static class CommandLineSend
{
    internal static async Task<int> RunAsync(string[] args)
    {
        if (args is not ["--send", var file, "--peer", var peer]
            || peer.Length != 12 || !peer.All(Uri.IsHexDigit)
            || !File.Exists(file))
        {
            Console.Error.WriteLine("DropPorter.exe --send <file> --peer <12 hex digits>");
            return 2;
        }
        var path = Path.GetFullPath(file);
        var mac = peer.ToLowerInvariant();
        var session = Native.DD_Create(0);
        if (session == 0) return 1;
        int Command(BridgeCommand command, string? text = null, int index = -1) =>
            Native.DD_Command(session, TransferMode.Send, command, text, index);
        int Value(ValueKind kind) => Native.DD_Value(session, TransferMode.Send, kind);
        try
        {
            if (Command(BridgeCommand.SelectPath, path) != 1 || Value(ValueKind.SendFileCount) != 1
                || Command(BridgeCommand.Start) != 1) return 1;
            var search = Stopwatch.StartNew();
            bool submitted = false;
            while (Value(ValueKind.TransferActive) == 1)
            {
                await Task.Delay(150);
                if (Command(BridgeCommand.Poll) != 1) return 1;
                if (submitted || Value(ValueKind.TransferActive) != 1) continue;
                int selection = Command(BridgeCommand.SendToPeer, mac);
                if (selection < 0 || (selection == 0 && search.Elapsed >= TimeSpan.FromSeconds(90))) return 1;
                submitted = selection == 1;
            }
            return Value(ValueKind.SendCompleted) == 1 ? 0 : 1;
        }
        finally
        {
            if (Value(ValueKind.TransferActive) == 1)
            {
                Command(BridgeCommand.Cancel);
                while (Value(ValueKind.TransferActive) == 1)
                {
                    await Task.Delay(150);
                    Command(BridgeCommand.Poll);
                }
            }
            // Restore a Wi-Fi state kept for further transfers before this process exits.
            if (Command(BridgeCommand.RequestClose) != 1)
            {
                while (Value(ValueKind.TransferActive) == 1)
                {
                    await Task.Delay(150);
                    Command(BridgeCommand.Poll);
                }
            }
            Native.DD_Destroy(session);
        }
    }
}
