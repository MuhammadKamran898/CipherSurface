using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CipherSurface.Data;
using CipherSurface.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace CipherSurface.Services;

/// <summary>Never put tokens in Data. Use strings, integers, booleans and nulls only (enums as strings).</summary>
public sealed record AuditEntry(
    Guid OrganizationId, string ActorType, Guid? ActorId, string Action, string EntityType, Guid? EntityId,
    IReadOnlyDictionary<string, object?>? Data = null, string? Ip = null);

/// <summary>
/// PostgreSQL's jsonb does not preserve key order or spacing, so the hash is computed over a canonical
/// form (sorted keys, compact) that survives a round trip through the database.
/// </summary>
public static class CanonicalJson
{
    public static string Normalize(string json)
    {
        using var document = JsonDocument.Parse(json);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
            Write(document.RootElement, writer);
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void Write(JsonElement element, Utf8JsonWriter writer)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    Write(property.Value, writer);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray()) Write(item, writer);
                writer.WriteEndArray();
                break;
            case JsonValueKind.String: writer.WriteStringValue(element.GetString()); break;
            case JsonValueKind.Number: writer.WriteRawValue(element.GetRawText()); break;
            case JsonValueKind.True: writer.WriteBooleanValue(true); break;
            case JsonValueKind.False: writer.WriteBooleanValue(false); break;
            default: writer.WriteNullValue(); break;
        }
    }
}

internal static class AuditHash
{
    public static byte[] Compute(byte[]? previousHash, AuditLog row)
    {
        var canonical = string.Join("\n",
            row.OrganizationId.ToString("D"),
            row.Sequence.ToString(CultureInfo.InvariantCulture),
            row.OccurredAt.UtcTicks.ToString(CultureInfo.InvariantCulture),
            row.ActorType,
            row.ActorId?.ToString("D") ?? "",
            row.Action,
            row.EntityType,
            row.EntityId?.ToString("D") ?? "",
            row.Data,
            row.Ip ?? "");
        var body = Encoding.UTF8.GetBytes(canonical);
        var previous = previousHash ?? Array.Empty<byte>();
        var all = new byte[previous.Length + body.Length];
        Buffer.BlockCopy(previous, 0, all, 0, previous.Length);
        Buffer.BlockCopy(body, 0, all, previous.Length, body.Length);
        return SHA256.HashData(all);
    }
}

/// <summary>
/// Appends to the per-organization hash chain. Must run inside a transaction: a transaction-scoped
/// advisory lock serializes writers of the same organization so sequence numbers never collide.
/// Calling this saves the context, so any other pending changes are saved with the entry.
/// </summary>
public sealed class AuditLogWriter
{
    private readonly TimeProvider _time;

    public AuditLogWriter(TimeProvider time) => _time = time;

    public async Task AppendAsync(CipherSurfaceDbContext db, AuditEntry entry, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is null)
            throw new InvalidOperationException("AuditLogWriter.AppendAsync must run inside a transaction.");

        await DbLocks.AcquireAsync(db, $"audit:{entry.OrganizationId:D}", ct);

        var last = await db.AuditLogs.AsNoTracking()
            .Where(a => a.OrganizationId == entry.OrganizationId)
            .OrderByDescending(a => a.Sequence)
            .Select(a => new { a.Sequence, a.Hash })
            .FirstOrDefaultAsync(ct);

        // PostgreSQL stores microseconds; truncate so the hash survives the round trip.
        var now = _time.GetUtcNow();
        var occurredAt = new DateTimeOffset(now.UtcTicks / 10 * 10, TimeSpan.Zero);

        var row = new AuditLog
        {
            Id = Guid.NewGuid(),
            OrganizationId = entry.OrganizationId,
            Sequence = (last?.Sequence ?? 0) + 1,
            OccurredAt = occurredAt,
            ActorType = entry.ActorType,
            ActorId = entry.ActorId,
            Action = entry.Action,
            EntityType = entry.EntityType,
            EntityId = entry.EntityId,
            Data = CanonicalJson.Normalize(entry.Data is null ? "{}" : JsonSerializer.Serialize(entry.Data)),
            Ip = entry.Ip,
            PrevHash = last?.Hash
        };
        row.Hash = AuditHash.Compute(row.PrevHash, row);

        db.AuditLogs.Add(row);
        await db.SaveChangesAsync(ct);
    }
}

public sealed record AuditChainResult(bool Intact, long? BrokenAtSequence, string? Problem);

public sealed class AuditChainVerifier
{
    public async Task<AuditChainResult> VerifyAsync(CipherSurfaceDbContext db, Guid organizationId, CancellationToken ct)
    {
        var rows = await db.AuditLogs.AsNoTracking()
            .Where(a => a.OrganizationId == organizationId)
            .OrderBy(a => a.Sequence)
            .ToListAsync(ct);

        byte[]? previous = null;
        long expected = 1;
        foreach (var row in rows)
        {
            if (row.Sequence != expected)
                return new AuditChainResult(false, expected, "A record is missing or duplicated.");
            if (!SameBytes(row.PrevHash, previous))
                return new AuditChainResult(false, row.Sequence, "The previous-hash link is broken.");

            row.Data = CanonicalJson.Normalize(row.Data);
            if (!SameBytes(AuditHash.Compute(previous, row), row.Hash))
                return new AuditChainResult(false, row.Sequence, "The record was changed after it was written.");

            previous = row.Hash;
            expected++;
        }
        return new AuditChainResult(true, null, null);
    }

    private static bool SameBytes(byte[]? a, byte[]? b) =>
        a is null || b is null ? a is null && b is null : a.AsSpan().SequenceEqual(b);
}
