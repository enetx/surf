package surf

func clearCachedTransports(_ *Response) error {
	cachedTransports.Range(func(key, _ any) bool { cachedTransports.Delete(key); return true })
	return nil
}
