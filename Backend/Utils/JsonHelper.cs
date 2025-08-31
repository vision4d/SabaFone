using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Dynamic;
using System.Text;

namespace SabaFone.Backend.Utils
{
    /// <summary>
    /// Helper class for JSON operations in SSAS
    /// </summary>
    public static class JsonHelper
    {
        private static readonly JsonSerializerOptions _defaultOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            ReferenceHandler = ReferenceHandler.IgnoreCycles,
            Converters =
            {
                new JsonStringEnumConverter(),
                new DateTimeConverterUsingDateTimeParse(),
                new GuidConverter()
            }
        };

        private static readonly JsonSerializerOptions _prettyOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            ReferenceHandler = ReferenceHandler.IgnoreCycles,
            Converters =
            {
                new JsonStringEnumConverter(),
                new DateTimeConverterUsingDateTimeParse(),
                new GuidConverter()
            }
        };

        #region Serialization

        /// <summary>
        /// Serializes an object to JSON string
        /// </summary>
        public static string Serialize<T>(T obj, bool indented = false)
        {
            if (obj == null)
                return "null";

            var options = indented ? _prettyOptions : _defaultOptions;
            return JsonSerializer.Serialize(obj, options);
        }

        /// <summary>
        /// Serializes an object to JSON bytes
        /// </summary>
        public static byte[] SerializeToBytes<T>(T obj)
        {
            if (obj == null)
                return Encoding.UTF8.GetBytes("null");

            return JsonSerializer.SerializeToUtf8Bytes(obj, _defaultOptions);
        }

        /// <summary>
        /// Serializes an object to a stream
        /// </summary>
        public static async Task SerializeToStreamAsync<T>(T obj, Stream stream)
        {
            await JsonSerializer.SerializeAsync(stream, obj, _defaultOptions);
        }

        /// <summary>
        /// Serializes an object to a file
        /// </summary>
        public static async Task SerializeToFileAsync<T>(T obj, string filePath, bool indented = false)
        {
            var options = indented ? _prettyOptions : _defaultOptions;
            
            using (var stream = File.Create(filePath))
            {
                await JsonSerializer.SerializeAsync(stream, obj, options);
            }
        }

        #endregion

        #region Deserialization

        /// <summary>
        /// Deserializes JSON string to object
        /// </summary>
        public static T Deserialize<T>(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
                return default;

            return JsonSerializer.Deserialize<T>(json, _defaultOptions);
        }

        /// <summary>
        /// Tries to deserialize JSON string to object
        /// </summary>
        public static bool TryDeserialize<T>(string json, out T result)
        {
            result = default;
            
            try
            {
                if (string.IsNullOrWhiteSpace(json))
                    return false;

                result = JsonSerializer.Deserialize<T>(json, _defaultOptions);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Deserializes JSON bytes to object
        /// </summary>
        public static T DeserializeFromBytes<T>(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
                return default;

            return JsonSerializer.Deserialize<T>(bytes, _defaultOptions);
        }

        /// <summary>
        /// Deserializes JSON from stream
        /// </summary>
        public static async Task<T> DeserializeFromStreamAsync<T>(Stream stream)
        {
            return await JsonSerializer.DeserializeAsync<T>(stream, _defaultOptions);
        }

        /// <summary>
        /// Deserializes JSON from file
        /// </summary>
        public static async Task<T> DeserializeFromFileAsync<T>(string filePath)
        {
            using (var stream = File.OpenRead(filePath))
            {
                return await JsonSerializer.DeserializeAsync<T>(stream, _defaultOptions);
            }
        }

        #endregion

        #region Dynamic JSON

        /// <summary>
        /// Parses JSON to dynamic object
        /// </summary>
        public static dynamic ParseDynamic(string json)
        {
            var jsonElement = JsonSerializer.Deserialize<JsonElement>(json);
            return ConvertJsonElementToDynamic(jsonElement);
        }

        /// <summary>
        /// Converts JsonElement to dynamic object
        /// </summary>
        private static dynamic ConvertJsonElementToDynamic(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    var expando = new ExpandoObject();
                    var dict = (IDictionary<string, object>)expando;
                    
                    foreach (var property in element.EnumerateObject())
                    {
                        dict[property.Name] = ConvertJsonElementToDynamic(property.Value);
                    }
                    return expando;

                case JsonValueKind.Array:
                    return element.EnumerateArray()
                        .Select(ConvertJsonElementToDynamic)
                        .ToList();

                case JsonValueKind.String:
                    return element.GetString();

                case JsonValueKind.Number:
                    if (element.TryGetInt32(out int intValue))
                        return intValue;
                    if (element.TryGetInt64(out long longValue))
                        return longValue;
                    return element.GetDouble();

                case JsonValueKind.True:
                    return true;

                case JsonValueKind.False:
                    return false;

                case JsonValueKind.Null:
                case JsonValueKind.Undefined:
                default:
                    return null;
            }
        }

        #endregion

        #region JSON Manipulation

        /// <summary>
        /// Merges two JSON objects
        /// </summary>
        public static string MergeJson(string json1, string json2)
        {
            var doc1 = JsonDocument.Parse(json1);
            var doc2 = JsonDocument.Parse(json2);
            
            using (var stream = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(stream))
                {
                    writer.WriteStartObject();
                    
                    // Write properties from first document
                    foreach (var property in doc1.RootElement.EnumerateObject())
                    {
                        property.WriteTo(writer);
                    }
                    
                    // Write/overwrite properties from second document
                    foreach (var property in doc2.RootElement.EnumerateObject())
                    {
                        property.WriteTo(writer);
                    }
                    
                    writer.WriteEndObject();
                }
                
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }

        /// <summary>
        /// Gets a value from JSON by path
        /// </summary>
        public static T GetValueByPath<T>(string json, string path)
        {
            var doc = JsonDocument.Parse(json);
            var pathParts = path.Split('.');
            JsonElement current = doc.RootElement;

            foreach (var part in pathParts)
            {
                if (current.ValueKind == JsonValueKind.Object)
                {
                    if (!current.TryGetProperty(part, out current))
                        return default;
                }
                else if (current.ValueKind == JsonValueKind.Array)
                {
                    if (int.TryParse(part, out int index))
                    {
                        if (index >= 0 && index < current.GetArrayLength())
                        {
                            current = current[index];
                        }
                        else
                        {
                            return default;
                        }
                    }
                    else
                    {
                        return default;
                    }
                }
                else
                {
                    return default;
                }
            }

            return JsonSerializer.Deserialize<T>(current.GetRawText());
        }

        /// <summary>
        /// Validates JSON string
        /// </summary>
        public static bool IsValidJson(string json)
        {
            try
            {
                JsonDocument.Parse(json);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Minifies JSON string
        /// </summary>
        public static string Minify(string json)
        {
            var doc = JsonDocument.Parse(json);
            return JsonSerializer.Serialize(doc, _defaultOptions);
        }

        /// <summary>
        /// Prettifies JSON string
        /// </summary>
        public static string Prettify(string json)
        {
            var doc = JsonDocument.Parse(json);
            return JsonSerializer.Serialize(doc, _prettyOptions);
        }

        #endregion

        #region Comparison

        /// <summary>
        /// Compares two JSON objects
        /// </summary>
        public static bool AreEqual(string json1, string json2)
        {
            try
            {
                var doc1 = JsonDocument.Parse(json1);
                var doc2 = JsonDocument.Parse(json2);
                return CompareElements(doc1.RootElement, doc2.RootElement);
            }
            catch
            {
                return false;
            }
        }

        private static bool CompareElements(JsonElement element1, JsonElement element2)
        {
            if (element1.ValueKind != element2.ValueKind)
                return false;

            switch (element1.ValueKind)
            {
                case JsonValueKind.Object:
                    var properties1 = element1.EnumerateObject().OrderBy(p => p.Name).ToList();
                    var properties2 = element2.EnumerateObject().OrderBy(p => p.Name).ToList();
                    
                    if (properties1.Count != properties2.Count)
                        return false;
                    
                    for (int i = 0; i < properties1.Count; i++)
                    {
                        if (properties1[i].Name != properties2[i].Name)
                            return false;
                        
                        if (!CompareElements(properties1[i].Value, properties2[i].Value))
                            return false;
                    }
                    return true;

                case JsonValueKind.Array:
                    if (element1.GetArrayLength() != element2.GetArrayLength())
                        return false;
                    
                    var array1 = element1.EnumerateArray().ToList();
                    var array2 = element2.EnumerateArray().ToList();
                    
                    for (int i = 0; i < array1.Count; i++)
                    {
                        if (!CompareElements(array1[i], array2[i]))
                            return false;
                    }
                    return true;

                case JsonValueKind.String:
                    return element1.GetString() == element2.GetString();

                case JsonValueKind.Number:
                    return element1.GetDouble() == element2.GetDouble();

                case JsonValueKind.True:
                case JsonValueKind.False:
                    return element1.GetBoolean() == element2.GetBoolean();

                case JsonValueKind.Null:
                    return true;

                default:
                    return false;
            }
        }

        #endregion

        #region Custom Converters

        /// <summary>
        /// Custom DateTime converter for flexible parsing
        /// </summary>
        private class DateTimeConverterUsingDateTimeParse : JsonConverter<DateTime>
        {
            public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                return DateTime.Parse(reader.GetString());
            }

            public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
            {
                writer.WriteStringValue(value.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
            }
        }

        /// <summary>
        /// Custom Guid converter
        /// </summary>
        private class GuidConverter : JsonConverter<Guid>
        {
            public override Guid Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                var value = reader.GetString();
                return string.IsNullOrEmpty(value) ? Guid.Empty : Guid.Parse(value);
            }

            public override void Write(Utf8JsonWriter writer, Guid value, JsonSerializerOptions options)
            {
                writer.WriteStringValue(value.ToString("D"));
            }
        }

        #endregion

        #region Schema Validation

        /// <summary>
        /// Validates JSON against a simple schema
        /// </summary>
        public static bool ValidateSchema(string json, Dictionary<string, Type> requiredFields)
        {
            try
            {
                var doc = JsonDocument.Parse(json);
                
                foreach (var field in requiredFields)
                {
                    if (!doc.RootElement.TryGetProperty(field.Key, out var element))
                        return false;
                    
                    // Simple type checking
                    if (field.Value == typeof(string) && element.ValueKind != JsonValueKind.String)
                        return false;
                    if (field.Value == typeof(int) && element.ValueKind != JsonValueKind.Number)
                        return false;
                    if (field.Value == typeof(bool) && 
                        element.ValueKind != JsonValueKind.True && 
                        element.ValueKind != JsonValueKind.False)
                        return false;
                }
                
                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion
    }
}