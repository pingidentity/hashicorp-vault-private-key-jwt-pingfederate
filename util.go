// Small JSON helpers shared across the path handlers.
//
// The duration type stores time.Duration values as human-readable strings
// in Vault storage and on read responses, instead of raw nanoseconds.
package pingfederate

import (
	"encoding/json"
	"time"
)

/* duration: */
// A time.Duration that JSON-encodes as a string ("24h0m0s").
// On decode it accepts either a duration string or a numeric nanosecond count.
type duration time.Duration

/* MarshalJSON: */
// Implements the json.Marshaler interface.
// Encodes as a quoted string instead of a raw number.
func (d duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

/* UnmarshalJSON: */
// Implements the json.Unmarshaler interface.
// Accepts either a duration string or a numeric nanosecond count.
func (d *duration) UnmarshalJSON(data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch val := v.(type) {
	case float64:
		*d = duration(time.Duration(val))
	case string:
		parsed, err := time.ParseDuration(val)
		if err != nil {
			return err
		}
		*d = duration(parsed)
	}
	return nil
}
