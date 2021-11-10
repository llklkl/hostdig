package log

type NopWriter struct{}

func (NopWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}
