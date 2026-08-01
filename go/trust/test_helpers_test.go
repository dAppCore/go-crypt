package trust

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func wantNoError(t testing.TB, err error, msgAndArgs ...any) {
	t.Helper()
	if err != nil {
		fail(t, fmt.Sprintf("unexpected error: %v", err), msgAndArgs...)
	}
}

func mustNoError(t testing.TB, err error, msgAndArgs ...any) {
	t.Helper()
	wantNoError(t, err, msgAndArgs...)
}

func wantError(t testing.TB, err error, msgAndArgs ...any) {
	t.Helper()
	if err == nil {
		fail(t, "expected error, got nil", msgAndArgs...)
	}
}

func mustError(t testing.TB, err error, msgAndArgs ...any) {
	t.Helper()
	wantError(t, err, msgAndArgs...)
}

func wantErrorIs(t testing.TB, err, target error, msgAndArgs ...any) {
	t.Helper()
	if !errors.Is(err, target) {
		fail(t, fmt.Sprintf("expected error %v, got %v", target, err), msgAndArgs...)
	}
}

func wantEqual(t testing.TB, want, got any, msgAndArgs ...any) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		fail(t, fmt.Sprintf("want %v, got %v", want, got), msgAndArgs...)
	}
}

func mustEqual(t testing.TB, want, got any, msgAndArgs ...any) {
	t.Helper()
	wantEqual(t, want, got, msgAndArgs...)
}

func wantNotEqual(t testing.TB, notWant, got any, msgAndArgs ...any) {
	t.Helper()
	if reflect.DeepEqual(notWant, got) {
		fail(t, fmt.Sprintf("did not want %v", got), msgAndArgs...)
	}
}

func wantTrue(t testing.TB, cond bool, msgAndArgs ...any) {
	t.Helper()
	if !cond {
		fail(t, "expected true", msgAndArgs...)
	}
}

func mustTrue(t testing.TB, cond bool, msgAndArgs ...any) {
	t.Helper()
	wantTrue(t, cond, msgAndArgs...)
}

func wantFalse(t testing.TB, cond bool, msgAndArgs ...any) {
	t.Helper()
	if cond {
		fail(t, "expected false", msgAndArgs...)
	}
}

func wantNil(t testing.TB, value any, msgAndArgs ...any) {
	t.Helper()
	if !isNil(value) {
		fail(t, fmt.Sprintf("expected nil, got %v", value), msgAndArgs...)
	}
}

func wantNotNil(t testing.TB, value any, msgAndArgs ...any) {
	t.Helper()
	if isNil(value) {
		fail(t, "expected non-nil", msgAndArgs...)
	}
}

func mustNotNil(t testing.TB, value any, msgAndArgs ...any) {
	t.Helper()
	wantNotNil(t, value, msgAndArgs...)
}

func wantEmpty(t testing.TB, value any, msgAndArgs ...any) {
	t.Helper()
	if !isEmpty(value) {
		fail(t, fmt.Sprintf("expected empty, got %v", value), msgAndArgs...)
	}
}

func wantNotEmpty(t testing.TB, value any, msgAndArgs ...any) {
	t.Helper()
	if isEmpty(value) {
		fail(t, "expected non-empty", msgAndArgs...)
	}
}

func mustNotEmpty(t testing.TB, value any, msgAndArgs ...any) {
	t.Helper()
	wantNotEmpty(t, value, msgAndArgs...)
}

func wantLen(t testing.TB, value any, want int, msgAndArgs ...any) {
	t.Helper()
	got, ok := lengthOf(value)
	if !ok {
		fail(t, fmt.Sprintf("expected value with length, got %T", value), msgAndArgs...)
	}
	if got != want {
		fail(t, fmt.Sprintf("expected length %d, got %d", want, got), msgAndArgs...)
	}
}

func mustLen(t testing.TB, value any, want int, msgAndArgs ...any) {
	t.Helper()
	wantLen(t, value, want, msgAndArgs...)
}

func wantContains(t testing.TB, collection, item any, msgAndArgs ...any) {
	t.Helper()
	if !containsValue(collection, item) {
		fail(t, fmt.Sprintf("expected %v to contain %v", collection, item), msgAndArgs...)
	}
}

func wantGreater(t testing.TB, got, threshold int, msgAndArgs ...any) {
	t.Helper()
	if got <= threshold {
		fail(t, fmt.Sprintf("expected %d to be greater than %d", got, threshold), msgAndArgs...)
	}
}

func wantNotPanic(t testing.TB, fn func(), msgAndArgs ...any) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			fail(t, fmt.Sprintf("unexpected panic: %v", recovered), msgAndArgs...)
		}
	}()
	fn()
}

func fail(t testing.TB, detail string, msgAndArgs ...any) {
	t.Helper()
	if len(msgAndArgs) > 0 {
		t.Fatalf("%s: %s", testMessage(msgAndArgs...), detail)
	}
	t.Fatal(detail)
}

func testMessage(msgAndArgs ...any) string {
	format, ok := msgAndArgs[0].(string)
	if ok && len(msgAndArgs) > 1 {
		return fmt.Sprintf(format, msgAndArgs[1:]...)
	}
	if ok {
		return format
	}
	return fmt.Sprint(msgAndArgs...)
}

func testMessagef(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func isEmpty(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	default:
		return v.IsZero()
	}
}

func lengthOf(value any) (int, bool) {
	if value == nil {
		return 0, false
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice, reflect.String:
		return v.Len(), true
	default:
		return 0, false
	}
}

func containsValue(collection, item any) bool {
	if s, ok := collection.(string); ok {
		substr, ok := item.(string)
		return ok && strings.Contains(s, substr)
	}

	v := reflect.ValueOf(collection)
	switch v.Kind() {
	case reflect.Array, reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			if reflect.DeepEqual(v.Index(i).Interface(), item) {
				return true
			}
		}
	case reflect.Map:
		key := reflect.ValueOf(item)
		if key.IsValid() && key.Type().AssignableTo(v.Type().Key()) {
			return v.MapIndex(key).IsValid()
		}
	}
	return false
}
