using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace SabaFone.Backend.Utils
{
    /// <summary>
    /// Helper class for DateTime operations in SSAS
    /// </summary>
    public static class DateTimeHelper
    {
        private static readonly TimeZoneInfo _defaultTimeZone = TimeZoneInfo.FindSystemTimeZoneById("Arabian Standard Time");

        #region DateTime Creation

        /// <summary>
        /// Gets current UTC time
        /// </summary>
        public static DateTime UtcNow => DateTime.UtcNow;

        /// <summary>
        /// Gets current time in default timezone (Arabian Standard Time)
        /// </summary>
        public static DateTime LocalNow => TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, _defaultTimeZone);

        /// <summary>
        /// Creates a DateTime for start of day
        /// </summary>
        public static DateTime StartOfDay(DateTime date)
        {
            return date.Date;
        }

        /// <summary>
        /// Creates a DateTime for end of day
        /// </summary>
        public static DateTime EndOfDay(DateTime date)
        {
            return date.Date.AddDays(1).AddTicks(-1);
        }

        /// <summary>
        /// Creates a DateTime for start of week
        /// </summary>
        public static DateTime StartOfWeek(DateTime date, DayOfWeek startOfWeek = DayOfWeek.Sunday)
        {
            int diff = (7 + (date.DayOfWeek - startOfWeek)) % 7;
            return date.AddDays(-1 * diff).Date;
        }

        /// <summary>
        /// Creates a DateTime for end of week
        /// </summary>
        public static DateTime EndOfWeek(DateTime date, DayOfWeek startOfWeek = DayOfWeek.Sunday)
        {
            return StartOfWeek(date, startOfWeek).AddDays(7).AddTicks(-1);
        }

        /// <summary>
        /// Creates a DateTime for start of month
        /// </summary>
        public static DateTime StartOfMonth(DateTime date)
        {
            return new DateTime(date.Year, date.Month, 1);
        }

        /// <summary>
        /// Creates a DateTime for end of month
        /// </summary>
        public static DateTime EndOfMonth(DateTime date)
        {
            return StartOfMonth(date).AddMonths(1).AddTicks(-1);
        }

        /// <summary>
        /// Creates a DateTime for start of year
        /// </summary>
        public static DateTime StartOfYear(DateTime date)
        {
            return new DateTime(date.Year, 1, 1);
        }

        /// <summary>
        /// Creates a DateTime for end of year
        /// </summary>
        public static DateTime EndOfYear(DateTime date)
        {
            return new DateTime(date.Year, 12, 31, 23, 59, 59, 999);
        }

        #endregion

        #region DateTime Conversion

        /// <summary>
        /// Converts DateTime to Unix timestamp
        /// </summary>
        public static long ToUnixTimestamp(DateTime dateTime)
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var utcDateTime = dateTime.ToUniversalTime();
            return (long)(utcDateTime - epoch).TotalSeconds;
        }

        /// <summary>
        /// Converts Unix timestamp to DateTime
        /// </summary>
        public static DateTime FromUnixTimestamp(long timestamp)
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return epoch.AddSeconds(timestamp);
        }

        /// <summary>
        /// Converts UTC to local timezone
        /// </summary>
        public static DateTime ConvertToLocal(DateTime utcDateTime, string timeZoneId = null)
        {
            var timeZone = string.IsNullOrEmpty(timeZoneId) 
                ? _defaultTimeZone 
                : TimeZoneInfo.FindSystemTimeZoneById(timeZoneId);
            
            return TimeZoneInfo.ConvertTimeFromUtc(utcDateTime, timeZone);
        }

        /// <summary>
        /// Converts local to UTC
        /// </summary>
        public static DateTime ConvertToUtc(DateTime localDateTime, string timeZoneId = null)
        {
            var timeZone = string.IsNullOrEmpty(timeZoneId) 
                ? _defaultTimeZone 
                : TimeZoneInfo.FindSystemTimeZoneById(timeZoneId);
            
            return TimeZoneInfo.ConvertTimeToUtc(localDateTime, timeZone);
        }

        /// <summary>
        /// Converts between time zones
        /// </summary>
        public static DateTime ConvertBetweenTimeZones(DateTime dateTime, string sourceTimeZoneId, string targetTimeZoneId)
        {
            var sourceTimeZone = TimeZoneInfo.FindSystemTimeZoneById(sourceTimeZoneId);
            var targetTimeZone = TimeZoneInfo.FindSystemTimeZoneById(targetTimeZoneId);
            
            return TimeZoneInfo.ConvertTime(dateTime, sourceTimeZone, targetTimeZone);
        }

        #endregion

        #region DateTime Formatting

        /// <summary>
        /// Formats DateTime as ISO 8601 string
        /// </summary>
        public static string ToIso8601(DateTime dateTime)
        {
            return dateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffK");
        }

        /// <summary>
        /// Formats DateTime as relative time (e.g., "2 hours ago")
        /// </summary>
        public static string ToRelativeTime(DateTime dateTime)
        {
            var timeSpan = DateTime.UtcNow - dateTime.ToUniversalTime();
            
            if (timeSpan.TotalSeconds < 60)
                return "just now";
            if (timeSpan.TotalMinutes < 60)
                return $"{(int)timeSpan.TotalMinutes} minute{((int)timeSpan.TotalMinutes == 1 ? "" : "s")} ago";
            if (timeSpan.TotalHours < 24)
                return $"{(int)timeSpan.TotalHours} hour{((int)timeSpan.TotalHours == 1 ? "" : "s")} ago";
            if (timeSpan.TotalDays < 7)
                return $"{(int)timeSpan.TotalDays} day{((int)timeSpan.TotalDays == 1 ? "" : "s")} ago";
            if (timeSpan.TotalDays < 30)
                return $"{(int)(timeSpan.TotalDays / 7)} week{((int)(timeSpan.TotalDays / 7) == 1 ? "" : "s")} ago";
            if (timeSpan.TotalDays < 365)
                return $"{(int)(timeSpan.TotalDays / 30)} month{((int)(timeSpan.TotalDays / 30) == 1 ? "" : "s")} ago";
            
            return $"{(int)(timeSpan.TotalDays / 365)} year{((int)(timeSpan.TotalDays / 365) == 1 ? "" : "s")} ago";
        }

        /// <summary>
        /// Formats DateTime for display
        /// </summary>
        public static string FormatForDisplay(DateTime dateTime, string format = "yyyy-MM-dd HH:mm:ss")
        {
            return dateTime.ToString(format);
        }

        /// <summary>
        /// Formats DateTime for Arabic culture
        /// </summary>
        public static string FormatArabic(DateTime dateTime)
        {
            var culture = new CultureInfo("ar-SA");
            return dateTime.ToString("dd MMMM yyyy", culture);
        }

        /// <summary>
        /// Formats DateTime for English culture
        /// </summary>
        public static string FormatEnglish(DateTime dateTime)
        {
            var culture = new CultureInfo("en-US");
            return dateTime.ToString("MMMM dd, yyyy", culture);
        }

        #endregion

        #region DateTime Calculation

        /// <summary>
        /// Calculates age from birthdate
        /// </summary>
        public static int CalculateAge(DateTime birthDate)
        {
            var today = DateTime.Today;
            var age = today.Year - birthDate.Year;
            
            if (birthDate.Date > today.AddYears(-age))
                age--;
            
            return age;
        }

        /// <summary>
        /// Gets business days between two dates
        /// </summary>
        public static int GetBusinessDays(DateTime startDate, DateTime endDate)
        {
            int businessDays = 0;
            var current = startDate.Date;
            
            while (current <= endDate.Date)
            {
                if (current.DayOfWeek != DayOfWeek.Friday && current.DayOfWeek != DayOfWeek.Saturday)
                    businessDays++;
                
                current = current.AddDays(1);
            }
            
            return businessDays;
        }

        /// <summary>
        /// Adds business days to a date
        /// </summary>
        public static DateTime AddBusinessDays(DateTime date, int businessDays)
        {
            var result = date;
            var daysToAdd = Math.Abs(businessDays);
            var direction = businessDays < 0 ? -1 : 1;
            
            while (daysToAdd > 0)
            {
                result = result.AddDays(direction);
                
                if (result.DayOfWeek != DayOfWeek.Friday && result.DayOfWeek != DayOfWeek.Saturday)
                    daysToAdd--;
            }
            
            return result;
        }

        /// <summary>
        /// Gets the quarter of a date
        /// </summary>
        public static int GetQuarter(DateTime date)
        {
            return (date.Month - 1) / 3 + 1;
        }

        /// <summary>
        /// Gets the week number of a date
        /// </summary>
        public static int GetWeekNumber(DateTime date)
        {
            var culture = CultureInfo.CurrentCulture;
            var calendar = culture.Calendar;
            var calendarWeekRule = culture.DateTimeFormat.CalendarWeekRule;
            var firstDayOfWeek = culture.DateTimeFormat.FirstDayOfWeek;
            
            return calendar.GetWeekOfYear(date, calendarWeekRule, firstDayOfWeek);
        }

        #endregion

        #region DateTime Validation

        /// <summary>
        /// Checks if date is weekend (Friday/Saturday in Saudi Arabia)
        /// </summary>
        public static bool IsWeekend(DateTime date)
        {
            return date.DayOfWeek == DayOfWeek.Friday || date.DayOfWeek == DayOfWeek.Saturday;
        }

        /// <summary>
        /// Checks if date is business day
        /// </summary>
        public static bool IsBusinessDay(DateTime date)
        {
            return !IsWeekend(date);
        }

        /// <summary>
        /// Checks if date is in the past
        /// </summary>
        public static bool IsPast(DateTime date)
        {
            return date < DateTime.UtcNow;
        }

        /// <summary>
        /// Checks if date is in the future
        /// </summary>
        public static bool IsFuture(DateTime date)
        {
            return date > DateTime.UtcNow;
        }

        /// <summary>
        /// Checks if date is today
        /// </summary>
        public static bool IsToday(DateTime date)
        {
            return date.Date == DateTime.Today;
        }

        /// <summary>
        /// Checks if date is within range
        /// </summary>
        public static bool IsInRange(DateTime date, DateTime start, DateTime end)
        {
            return date >= start && date <= end;
        }

        #endregion

        #region DateTime Parsing

        /// <summary>
        /// Tries to parse date string with multiple formats
        /// </summary>
        public static bool TryParseDateString(string dateString, out DateTime result)
        {
            result = default;
            
            if (string.IsNullOrWhiteSpace(dateString))
                return false;

            var formats = new[]
            {
                "yyyy-MM-dd",
                "yyyy-MM-dd HH:mm:ss",
                "yyyy-MM-ddTHH:mm:ss",
                "yyyy-MM-ddTHH:mm:ssZ",
                "yyyy-MM-ddTHH:mm:ss.fff",
                "yyyy-MM-ddTHH:mm:ss.fffZ",
                "dd/MM/yyyy",
                "dd/MM/yyyy HH:mm:ss",
                "MM/dd/yyyy",
                "MM/dd/yyyy HH:mm:ss",
                "dd-MM-yyyy",
                "dd-MM-yyyy HH:mm:ss"
            };

            return DateTime.TryParseExact(
                dateString, 
                formats, 
                CultureInfo.InvariantCulture, 
                DateTimeStyles.None, 
                out result);
        }

        /// <summary>
        /// Parses relative date string (e.g., "tomorrow", "next week")
        /// </summary>
        public static DateTime? ParseRelativeDate(string relativeDate)
        {
            var input = relativeDate.ToLower().Trim();
            var now = DateTime.Now;

            return input switch
            {
                "today" => now.Date,
                "tomorrow" => now.Date.AddDays(1),
                "yesterday" => now.Date.AddDays(-1),
                "next week" => StartOfWeek(now.AddDays(7)),
                "last week" => StartOfWeek(now.AddDays(-7)),
                "next month" => StartOfMonth(now.AddMonths(1)),
                "last month" => StartOfMonth(now.AddMonths(-1)),
                "next year" => StartOfYear(now.AddYears(1)),
                "last year" => StartOfYear(now.AddYears(-1)),
                _ => null
            };
        }

        #endregion

        #region Date Ranges

        /// <summary>
        /// Gets date range for period
        /// </summary>
        public static (DateTime start, DateTime end) GetDateRange(string period)
        {
            var now = DateTime.UtcNow;
            
            return period.ToLower() switch
            {
                "today" => (StartOfDay(now), EndOfDay(now)),
                "yesterday" => (StartOfDay(now.AddDays(-1)), EndOfDay(now.AddDays(-1))),
                "thisweek" => (StartOfWeek(now), EndOfWeek(now)),
                "lastweek" => (StartOfWeek(now.AddDays(-7)), EndOfWeek(now.AddDays(-7))),
                "thismonth" => (StartOfMonth(now), EndOfMonth(now)),
                "lastmonth" => (StartOfMonth(now.AddMonths(-1)), EndOfMonth(now.AddMonths(-1))),
                "thisyear" => (StartOfYear(now), EndOfYear(now)),
                "lastyear" => (StartOfYear(now.AddYears(-1)), EndOfYear(now.AddYears(-1))),
                "last7days" => (now.AddDays(-7), now),
                "last30days" => (now.AddDays(-30), now),
                "last90days" => (now.AddDays(-90), now),
                _ => (now, now)
            };
        }

        /// <summary>
        /// Generates date range list
        /// </summary>
        public static List<DateTime> GetDateList(DateTime start, DateTime end, TimeSpan interval)
        {
            var dates = new List<DateTime>();
            var current = start;
            
            while (current <= end)
            {
                dates.Add(current);
                current = current.Add(interval);
            }
            
            return dates;
        }

        #endregion
    }
}