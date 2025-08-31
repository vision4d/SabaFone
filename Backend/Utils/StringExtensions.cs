using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SabaFone.Backend.Utils
{
    /// <summary>
    /// String extension methods for SSAS
    /// </summary>
    public static class StringExtensions
    {
        #region Validation Extensions

        /// <summary>
        /// Checks if string is null or empty
        /// </summary>
        public static bool IsNullOrEmpty(this string value)
        {
            return string.IsNullOrEmpty(value);
        }

        /// <summary>
        /// Checks if string is null or whitespace
        /// </summary>
        public static bool IsNullOrWhiteSpace(this string value)
        {
            return string.IsNullOrWhiteSpace(value);
        }

        /// <summary>
        /// Checks if string has value
        /// </summary>
        public static bool HasValue(this string value)
        {
            return !string.IsNullOrWhiteSpace(value);
        }

        /// <summary>
        /// Validates email format
        /// </summary>
        public static bool IsValidEmail(this string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            try
            {
                var pattern = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";
                var regex = new Regex(pattern, RegexOptions.IgnoreCase);
                return regex.IsMatch(email);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Validates phone number format
        /// </summary>
        public static bool IsValidPhoneNumber(this string phone)
        {
            if (string.IsNullOrWhiteSpace(phone))
                return false;

            // Saudi phone number pattern
            var pattern = @"^(\+966|0)?5[0-9]{8}$";
            return Regex.IsMatch(phone, pattern);
        }

        /// <summary>
        /// Validates URL format
        /// </summary>
        public static bool IsValidUrl(this string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return false;

            return Uri.TryCreate(url, UriKind.Absolute, out var result) &&
                   (result.Scheme == Uri.UriSchemeHttp || result.Scheme == Uri.UriSchemeHttps);
        }

        /// <summary>
        /// Validates IP address
        /// </summary>
        public static bool IsValidIpAddress(this string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            var pattern = @"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";
            return Regex.IsMatch(ipAddress, pattern);
        }

        /// <summary>
        /// Checks if string is numeric
        /// </summary>
        public static bool IsNumeric(this string value)
        {
            return !string.IsNullOrWhiteSpace(value) && value.All(char.IsDigit);
        }

        /// <summary>
        /// Checks if string is alphanumeric
        /// </summary>
        public static bool IsAlphanumeric(this string value)
        {
            return !string.IsNullOrWhiteSpace(value) && value.All(char.IsLetterOrDigit);
        }

        #endregion

        #region Transformation Extensions

        /// <summary>
        /// Truncates string to specified length
        /// </summary>
        public static string Truncate(this string value, int maxLength, string suffix = "...")
        {
            if (string.IsNullOrEmpty(value))
                return value;

            if (value.Length <= maxLength)
                return value;

            return value.Substring(0, maxLength - suffix.Length) + suffix;
        }

        /// <summary>
        /// Removes HTML tags from string
        /// </summary>
        public static string StripHtml(this string html)
        {
            if (string.IsNullOrEmpty(html))
                return html;

            return Regex.Replace(html, "<.*?>", string.Empty);
        }

        /// <summary>
        /// Converts string to title case
        /// </summary>
        public static string ToTitleCase(this string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return value;

            var textInfo = CultureInfo.CurrentCulture.TextInfo;
            return textInfo.ToTitleCase(value.ToLower());
        }

        /// <summary>
        /// Converts string to camel case
        /// </summary>
        public static string ToCamelCase(this string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return value;

            var words = value.Split(new[] { ' ', '_', '-' }, StringSplitOptions.RemoveEmptyEntries);
            
            if (words.Length == 0)
                return value;

            var result = words[0].ToLower();
            for (int i = 1; i < words.Length; i++)
            {
                result += words[i].Substring(0, 1).ToUpper() + words[i].Substring(1).ToLower();
            }

            return result;
        }

        /// <summary>
        /// Converts string to pascal case
        /// </summary>
        public static string ToPascalCase(this string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return value;

            var words = value.Split(new[] { ' ', '_', '-' }, StringSplitOptions.RemoveEmptyEntries);
            
            return string.Join("", words.Select(w => 
                w.Substring(0, 1).ToUpper() + w.Substring(1).ToLower()));
        }

        /// <summary>
        /// Converts string to snake case
        /// </summary>
        public static string ToSnakeCase(this string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return value;

            return Regex.Replace(value, @"([a-z0-9])([A-Z])", "$1_$2").ToLower();
        }

        /// <summary>
        /// Converts string to kebab case
        /// </summary>
        public static string ToKebabCase(this string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return value;

            return Regex.Replace(value, @"([a-z0-9])([A-Z])", "$1-$2").ToLower();
        }

        /// <summary>
        /// Reverses a string
        /// </summary>
        public static string Reverse(this string value)
        {
            if (string.IsNullOrEmpty(value))
                return value;

            return new string(value.ToCharArray().Reverse().ToArray());
        }

        /// <summary>
        /// Removes special characters
        /// </summary>
        public static string RemoveSpecialCharacters(this string value)
        {
            if (string.IsNullOrEmpty(value))
                return value;

            return Regex.Replace(value, @"[^a-zA-Z0-9\s]", "");
        }

        /// <summary>
        /// Normalizes whitespace
        /// </summary>
        public static string NormalizeWhitespace(this string value)
        {
            if (string.IsNullOrEmpty(value))
                return value;

            return Regex.Replace(value.Trim(), @"\s+", " ");
        }

        #endregion

        #region Parsing Extensions

        /// <summary>
        /// Safely parses string to int
        /// </summary>
        public static int? ToInt(this string value)
        {
            return int.TryParse(value, out var result) ? result : (int?)null;
        }

        /// <summary>
        /// Safely parses string to long
        /// </summary>
        public static long? ToLong(this string value)
        {
            return long.TryParse(value, out var result) ? result : (long?)null;
        }

        /// <summary>
        /// Safely parses string to double
        /// </summary>
        public static double? ToDouble(this string value)
        {
            return double.TryParse(value, out var result) ? result : (double?)null;
        }

        /// <summary>
        /// Safely parses string to decimal
        /// </summary>
        public static decimal? ToDecimal(this string value)
        {
            return decimal.TryParse(value, out var result) ? result : (decimal?)null;
        }

        /// <summary>
        /// Safely parses string to bool
        /// </summary>
        public static bool? ToBool(this string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;

            value = value.Trim().ToLower();
            
            if (value == "true" || value == "yes" || value == "1")
                return true;
            
            if (value == "false" || value == "no" || value == "0")
                return false;
            
            return null;
        }

        /// <summary>
        /// Safely parses string to DateTime
        /// </summary>
        public static DateTime? ToDateTime(this string value)
        {
            return DateTime.TryParse(value, out var result) ? result : (DateTime?)null;
        }

        /// <summary>
        /// Safely parses string to Guid
        /// </summary>
        public static Guid? ToGuid(this string value)
        {
            return Guid.TryParse(value, out var result) ? result : (Guid?)null;
        }

        /// <summary>
        /// Safely parses string to enum
        /// </summary>
        public static T? ToEnum<T>(this string value) where T : struct, Enum
        {
            return Enum.TryParse<T>(value, true, out var result) ? result : (T?)null;
        }

        #endregion

        #region Security Extensions

        /// <summary>
        /// Masks sensitive data
        /// </summary>
        public static string Mask(this string value, int visibleChars = 4, char maskChar = '*')
        {
            if (string.IsNullOrEmpty(value))
                return value;

            if (value.Length <= visibleChars)
                return new string(maskChar, value.Length);

            var visible = value.Substring(value.Length - visibleChars);
            var masked = new string(maskChar, value.Length - visibleChars);
            
            return masked + visible;
        }

        /// <summary>
        /// Sanitizes input for SQL
        /// </summary>
        public static string SanitizeSql(this string value)
        {
            if (string.IsNullOrEmpty(value))
                return value;

            // Remove dangerous SQL keywords
            var dangerous = new[] { "--", "/*", "*/", "xp_", "sp_", "exec", "execute", "drop", "alter", "create" };
            
            foreach (var keyword in dangerous)
            {
                value = value.Replace(keyword, "", StringComparison.OrdinalIgnoreCase);
            }

            return value;
        }

        /// <summary>
        /// Sanitizes input for HTML
        /// </summary>
        public static string SanitizeHtml(this string value)
        {
            if (string.IsNullOrEmpty(value))
                return value;

            value = value.Replace("<", "&lt;");
            value = value.Replace(">", "&gt;");
            value = value.Replace("\"", "&quot;");
            value = value.Replace("'", "&#x27;");
            value = value.Replace("/", "&#x2F;");

            return value;
        }

        /// <summary>
        /// Generates a slug from string
        /// </summary>
        public static string ToSlug(this string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return value;

            // Remove accents
            value = RemoveAccents(value);
            
            // Convert to lowercase
            value = value.ToLowerInvariant();
            
            // Replace spaces with hyphens
            value = Regex.Replace(value, @"\s", "-", RegexOptions.Compiled);
            
            // Remove invalid characters
            value = Regex.Replace(value, @"[^a-z0-9\s-_]", "", RegexOptions.Compiled);
            
            // Remove multiple hyphens
            value = Regex.Replace(value, @"-+", "-", RegexOptions.Compiled);
            
            // Trim hyphens
            value = value.Trim('-', '_');

            return value;
        }

        #endregion

        #region Encoding Extensions

        /// <summary>
        /// Encodes string to Base64
        /// </summary>
        public static string ToBase64(this string value)
        {
            if (string.IsNullOrEmpty(value))
                return value;

            var bytes = Encoding.UTF8.GetBytes(value);
            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// Decodes string from Base64
        /// </summary>
        public static string FromBase64(this string value)
        {
            if (string.IsNullOrEmpty(value))
                return value;

            try
            {
                var bytes = Convert.FromBase64String(value);
                return Encoding.UTF8.GetString(bytes);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// URL encodes a string
        /// </summary>
        public static string UrlEncode(this string value)
        {
            return Uri.EscapeDataString(value ?? "");
        }

        /// <summary>
        /// URL decodes a string
        /// </summary>
        public static string UrlDecode(this string value)
        {
            return Uri.UnescapeDataString(value ?? "");
        }

        #endregion

        #region Comparison Extensions

        /// <summary>
        /// Case-insensitive equals
        /// </summary>
        public static bool EqualsIgnoreCase(this string value, string other)
        {
            return string.Equals(value, other, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Case-insensitive contains
        /// </summary>
        public static bool ContainsIgnoreCase(this string value, string search)
        {
            if (value == null || search == null)
                return false;

            return value.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>
        /// Case-insensitive starts with
        /// </summary>
        public static bool StartsWithIgnoreCase(this string value, string search)
        {
            if (value == null || search == null)
                return false;

            return value.StartsWith(search, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Case-insensitive ends with
        /// </summary>
        public static bool EndsWithIgnoreCase(this string value, string search)
        {
            if (value == null || search == null)
                return false;

            return value.EndsWith(search, StringComparison.OrdinalIgnoreCase);
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Removes accents from string
        /// </summary>
        private static string RemoveAccents(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return text;

            var normalizedString = text.Normalize(NormalizationForm.FormD);
            var stringBuilder = new StringBuilder();

            foreach (var c in normalizedString)
            {
                var unicodeCategory = CharUnicodeInfo.GetUnicodeCategory(c);
                if (unicodeCategory != UnicodeCategory.NonSpacingMark)
                {
                    stringBuilder.Append(c);
                }
            }

            return stringBuilder.ToString().Normalize(NormalizationForm.FormC);
        }

        /// <summary>
        /// Gets string between two strings
        /// </summary>
        public static string GetBetween(this string value, string start, string end)
        {
            if (string.IsNullOrEmpty(value))
                return value;

            var startIndex = value.IndexOf(start);
            if (startIndex < 0)
                return null;

            startIndex += start.Length;
            var endIndex = value.IndexOf(end, startIndex);
            
            if (endIndex < 0)
                return null;

            return value.Substring(startIndex, endIndex - startIndex);
        }

        /// <summary>
        /// Splits string and trims results
        /// </summary>
        public static string[] SplitAndTrim(this string value, params char[] separators)
        {
            if (string.IsNullOrEmpty(value))
                return Array.Empty<string>();

            return value.Split(separators)
                .Select(s => s.Trim())
                .Where(s => !string.IsNullOrEmpty(s))
                .ToArray();
        }

        /// <summary>
        /// Ensures string ends with suffix
        /// </summary>
        public static string EnsureEndsWith(this string value, string suffix)
        {
            if (string.IsNullOrEmpty(value))
                return suffix;

            if (value.EndsWith(suffix))
                return value;

            return value + suffix;
        }

        /// <summary>
        /// Ensures string starts with prefix
        /// </summary>
        public static string EnsureStartsWith(this string value, string prefix)
        {
            if (string.IsNullOrEmpty(value))
                return prefix;

            if (value.StartsWith(prefix))
                return value;

            return prefix + value;
        }

        #endregion
    }
}