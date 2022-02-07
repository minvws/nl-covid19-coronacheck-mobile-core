package mobilecore

import (
	"fmt"
	"github.com/go-errors/errors"
	"strconv"
	"time"
)

// To handle the special case of BG including full ISO8601 date strings, all strings are
//   reduced to their maximum length, so any following invalid information is ignored
func truncateDateString(value string) string {
	if len(value) > 10 {
		return value[:10]
	}

	return value
}

func parseDate(value string) (time.Time, error) {
	truncatedValue := truncateDateString(value)
	return time.Parse(YYYYMMDD_FORMAT, truncatedValue)
}

func parseDateOfBirth(value string) (year, month, day string, err error) {
	truncatedValue := truncateDateString(value)

	// Birth dates may have the day absent, or both day and month absent
	res := DATE_OF_BIRTH_REGEX.FindStringSubmatch(truncatedValue)
	if len(res) != 4 {
		return "", "", "", errors.Errorf("Did not conform to regex")
	}

	return res[1], res[2], res[3], nil
}

// Parses the birthdate to a time value and takes the highest / most recent values for the month and day
//  in case those values are unknown, but takes an old year if the year is unknown
func mostRecentDOBDayMonth(value string) (time.Time, error) {
	year, month, day, err := parseDateOfBirth(value)
	if err != nil {
		return time.Time{}, errors.WrapPrefix(err, "Could not parse date of birth", 0)
	}

	if year == "" {
		year = "1900"
	}

	if month == "" {
		month = "12"
	}

	if day == "" {
		dayNumber, err := daysIn(month, year)
		if err != nil {
			return time.Time{}, errors.WrapPrefix(err, "Could not get days in month", 0)
		}

		day = strconv.Itoa(dayNumber)
	}

	dobTime, err := parseDate(fmt.Sprintf("%s-%s-%s", year, month, day))
	if err != nil {
		return time.Time{}, errors.WrapPrefix(err, "Could not parse most recent date of birth", 0)
	}

	return dobTime, nil
}

// Unfortunately time.Time doesn't export daysIn, so we have to copy a fair amount of it,
//  although we'll change some types
var daysBefore = [...]int32{
	0,
	31,
	31 + 28,
	31 + 28 + 31,
	31 + 28 + 31 + 30,
	31 + 28 + 31 + 30 + 31,
	31 + 28 + 31 + 30 + 31 + 30,
	31 + 28 + 31 + 30 + 31 + 30 + 31,
	31 + 28 + 31 + 30 + 31 + 30 + 31 + 31,
	31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30,
	31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31,
	31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30,
	31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30 + 31,
}

func isLeap(year int) bool {
	return year%4 == 0 && (year%100 != 0 || year%400 == 0)
}

func daysIn(monthString string, yearString string) (int, error) {
	monthNumber, err := strconv.Atoi(monthString)
	if err != nil {
		return 0, errors.WrapPrefix(err, "Could not parse month as integer", 0)
	}

	yearNumber, err := strconv.Atoi(yearString)
	if err != nil {
		return 0, errors.WrapPrefix(err, "Could not parse year as integer", 0)
	}

	if time.Month(monthNumber) == time.February && isLeap(yearNumber) {
		return 29, nil
	}
	return int(daysBefore[monthNumber] - daysBefore[monthNumber-1]), nil
}
