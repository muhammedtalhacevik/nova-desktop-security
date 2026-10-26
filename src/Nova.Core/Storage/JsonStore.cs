using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Nova.Core.Storage;

public sealed class JsonStore<T> where T : class, new()
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly string _path;
    private readonly object _gate = new();

    public JsonStore(string fileName)
    {
        _path = Path.Combine(AppPaths.Data, fileName);
    }

    public T Load()
    {
        lock (_gate)
        {
            try
            {
                if (File.Exists(_path))
                    return JsonSerializer.Deserialize<T>(File.ReadAllText(_path), Options) ?? new T();
            }
            catch (Exception)
            {
                try { File.Copy(_path, _path + ".corrupt", true); } catch { }
            }
            return new T();
        }
    }

    public static event Action<string, Exception>? SaveFailed;

    public void Save(T value)
    {
        lock (_gate)
        {
            var tmp = _path + ".tmp";
            try
            {
                File.WriteAllText(tmp, JsonSerializer.Serialize(value, Options));
                File.Move(tmp, _path, true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                try { File.Delete(tmp); } catch { }
                SaveFailed?.Invoke(_path, ex);
            }
        }
    }
}
