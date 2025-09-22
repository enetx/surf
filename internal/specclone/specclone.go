// Package specclone provides deep cloning functionality for uTLS ClientHelloSpec structures.
//
// This package is essential for creating independent copies of TLS client specifications
// without sharing memory references, preventing unintended mutations between cloned instances.
//
// The package handles complete cloning of utls.ClientHelloSpec structures, including:
//   - Basic fields (TLS versions, cipher suites, compression methods)
//   - Complex nested extension structures (20+ supported extension types)
//   - Dynamic extension types through reflection-based cloning
//   - Safe handling of nil pointers and empty collections
//
// Example usage:
//
//	spec, err := utls.UTLSIdToSpec(utls.HelloFirefox_120)
//	if err != nil {
//		panic(err)
//	}
//
//	// Clone the spec
//	cloned := specclone.SpecClone(&spec)
//
//	// Modifications to original don't affect clone
//	spec.TLSVersMin = 0x0301  // Change original
//	// cloned.TLSVersMin remains unchanged
//
// The cloning process ensures:
//   - No shared memory references between original and clone
//   - Safe handling of nil pointers at all levels
//   - Proper deep copying of nested data structures
//   - Thread-safe operations (no shared mutable state)
//
// Performance considerations:
//   - Uses reflection for unknown extension types (performance overhead)
//   - Creates complete copies of all data structures
//   - Memory usage scales with complexity of input specification
package specclone

import (
	"reflect"
	"unsafe"

	utls "github.com/enetx/utls"
)

// Clone creates a deep copy of a utls.ClientHelloSpec.
//
// This function performs complete deep cloning of all fields and nested structures,
// ensuring the returned clone is completely independent from the original.
//
// Parameters:
//   - c: Pointer to the source ClientHelloSpec to clone
//
// Returns:
//   - Pointer to a new ClientHelloSpec with all fields deeply copied
//   - Returns nil if input is nil
//
// The function handles:
//   - Basic fields: TLSVersMin, TLSVersMax, GetSessionID
//   - Slices: CipherSuites, CompressionMethods (with independent memory)
//   - Extensions: All supported extension types with proper deep copying
//
// Supported extension types include:
//   - SNIExtension, ALPNExtension, StatusRequestExtension
//   - SupportedCurvesExtension, SignatureAlgorithmsExtension
//   - KeyShareExtension, SessionTicketExtension, PreSharedKeyExtension
//   - And 15+ more extension types
//
// For unknown extension types, the function falls back to reflection-based
// deep cloning to ensure completeness.
func Clone(c *utls.ClientHelloSpec) *utls.ClientHelloSpec {
	if c == nil {
		return nil
	}

	clone := &utls.ClientHelloSpec{
		TLSVersMin:   c.TLSVersMin,
		TLSVersMax:   c.TLSVersMax,
		GetSessionID: c.GetSessionID,
	}

	if c.CipherSuites != nil {
		clone.CipherSuites = append([]uint16{}, c.CipherSuites...)
	}

	if c.CompressionMethods != nil {
		clone.CompressionMethods = append([]uint8{}, c.CompressionMethods...)
	}

	if c.Extensions != nil {
		clone.Extensions = make([]utls.TLSExtension, len(c.Extensions))
		for i, ext := range c.Extensions {
			if ext != nil {
				clone.Extensions[i] = deepCloneExtension(ext)
			}
		}
	}

	return clone
}

// deepCloneExtension performs type-specific deep cloning of TLS extensions.
//
// This function handles the cloning of individual TLS extensions based on their
// concrete type. It supports over 20 different extension types with proper
// deep copying of their internal state and nested structures.
//
// For each supported extension type, the function:
//   - Creates a new instance of the same type
//   - Deep copies all fields including slices and nested structs
//   - Ensures complete memory independence from the original
//
// Supported extension types:
//   - SNIExtension: Server Name Indication
//   - ALPNExtension: Application Layer Protocol Negotiation
//   - SupportedCurvesExtension: Elliptic Curves
//   - SignatureAlgorithmsExtension: Signature Algorithms
//   - KeyShareExtension: Key Exchange with deep copying of key data
//   - SessionTicketExtension: Session tickets with SessionState cloning
//   - PreSharedKeyExtension: Both Fake and Utls variants
//   - And many more specialized extensions
//
// For extensions not explicitly handled, the function falls back to
// reflection-based deep cloning via deepCloneInterface.
//
// Parameters:
//   - ext: The TLS extension to clone
//
// Returns:
//   - A deeply cloned copy of the extension with the same concrete type
func deepCloneExtension(ext utls.TLSExtension) utls.TLSExtension {
	switch e := ext.(type) {
	case *utls.SNIExtension:
		return &utls.SNIExtension{
			ServerName: e.ServerName,
		}
	case *utls.StatusRequestExtension:
		return &utls.StatusRequestExtension{}
	case *utls.SupportedCurvesExtension:
		return &utls.SupportedCurvesExtension{
			Curves: append([]utls.CurveID{}, e.Curves...),
		}
	case *utls.SupportedPointsExtension:
		return &utls.SupportedPointsExtension{
			SupportedPoints: append([]uint8{}, e.SupportedPoints...),
		}
	case *utls.SignatureAlgorithmsExtension:
		return &utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: append([]utls.SignatureScheme{}, e.SupportedSignatureAlgorithms...),
		}
	case *utls.ALPNExtension:
		return &utls.ALPNExtension{
			AlpnProtocols: append([]string{}, e.AlpnProtocols...),
		}
	case *utls.StatusRequestV2Extension:
		return &utls.StatusRequestV2Extension{}
	case *utls.SCTExtension:
		return &utls.SCTExtension{}
	case *utls.UtlsPaddingExtension:
		return &utls.UtlsPaddingExtension{
			PaddingLen:    e.PaddingLen,
			WillPad:       e.WillPad,
			GetPaddingLen: e.GetPaddingLen,
		}
	case *utls.ExtendedMasterSecretExtension:
		return &utls.ExtendedMasterSecretExtension{}
	case *utls.FakeTokenBindingExtension:
		return &utls.FakeTokenBindingExtension{
			MajorVersion:  e.MajorVersion,
			MinorVersion:  e.MinorVersion,
			KeyParameters: append([]uint8{}, e.KeyParameters...),
		}
	case *utls.UtlsCompressCertExtension:
		return &utls.UtlsCompressCertExtension{
			Algorithms: append([]utls.CertCompressionAlgo{}, e.Algorithms...),
		}
	case *utls.FakeRecordSizeLimitExtension:
		return &utls.FakeRecordSizeLimitExtension{
			Limit: e.Limit,
		}
	case *utls.FakeDelegatedCredentialsExtension:
		return &utls.FakeDelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: append([]utls.SignatureScheme{}, e.SupportedSignatureAlgorithms...),
		}
	case *utls.SessionTicketExtension:
		var session *utls.SessionState
		if e.Session != nil {
			extra := make([][]byte, len(e.Session.Extra))
			for i, b := range e.Session.Extra {
				if b != nil {
					extra[i] = append([]byte{}, b...)
				}
			}

			session = &utls.SessionState{
				Extra:     extra,
				EarlyData: e.Session.EarlyData,
			}
		}

		return &utls.SessionTicketExtension{
			Session:     session,
			Ticket:      append([]byte{}, e.Ticket...),
			Initialized: e.Initialized,
		}
	case *utls.FakePreSharedKeyExtension:
		clonedIdentities := make([]utls.PskIdentity, len(e.Identities))
		for i, id := range e.Identities {
			clonedIdentities[i] = utls.PskIdentity{
				Label:               append([]byte{}, id.Label...),
				ObfuscatedTicketAge: id.ObfuscatedTicketAge,
			}
		}

		clonedBinders := make([][]byte, len(e.Binders))
		for i, b := range e.Binders {
			if b != nil {
				clonedBinders[i] = append([]byte{}, b...)
			}
		}

		return &utls.FakePreSharedKeyExtension{
			Identities: clonedIdentities,
			Binders:    clonedBinders,
		}
	case *utls.UtlsPreSharedKeyExtension:
		clonedIdentities := make([]utls.PskIdentity, len(e.Identities))
		for i, id := range e.Identities {
			clonedIdentities[i] = utls.PskIdentity{
				Label:               append([]byte{}, id.Label...),
				ObfuscatedTicketAge: id.ObfuscatedTicketAge,
			}
		}

		clonedBinders := make([][]byte, len(e.Binders))
		for i, b := range e.Binders {
			if b != nil {
				clonedBinders[i] = append([]byte{}, b...)
			}
		}

		var clonedSession *utls.SessionState
		if e.Session != nil {
			extra := make([][]byte, len(e.Session.Extra))
			for i, b := range e.Session.Extra {
				if b != nil {
					extra[i] = append([]byte{}, b...)
				}
			}
			clonedSession = &utls.SessionState{
				Extra:     extra,
				EarlyData: e.Session.EarlyData,
			}
		}

		return &utls.UtlsPreSharedKeyExtension{
			PreSharedKeyCommon: utls.PreSharedKeyCommon{
				Identities:  clonedIdentities,
				Binders:     clonedBinders,
				BinderKey:   append([]byte{}, e.BinderKey...),
				EarlySecret: append([]byte{}, e.EarlySecret...),
				Session:     clonedSession,
			},
			OmitEmptyPsk: e.OmitEmptyPsk,
		}
	case *utls.SupportedVersionsExtension:
		return &utls.SupportedVersionsExtension{
			Versions: append([]uint16{}, e.Versions...),
		}
	case *utls.CookieExtension:
		return &utls.CookieExtension{
			Cookie: append([]byte{}, e.Cookie...),
		}
	case *utls.PSKKeyExchangeModesExtension:
		return &utls.PSKKeyExchangeModesExtension{
			Modes: append([]uint8{}, e.Modes...),
		}
	case *utls.SignatureAlgorithmsCertExtension:
		return &utls.SignatureAlgorithmsCertExtension{
			SupportedSignatureAlgorithms: append([]utls.SignatureScheme{}, e.SupportedSignatureAlgorithms...),
		}
	case *utls.KeyShareExtensionExtended:
		var keyShares []utls.KeyShare
		if e.KeyShareExtension != nil {
			keyShares = make([]utls.KeyShare, len(e.KeyShares))
			for i, ks := range e.KeyShares {
				keyShares[i] = utls.KeyShare{
					Group: ks.Group,
					Data:  append([]byte{}, ks.Data...),
				}
			}
		}
		return &utls.KeyShareExtensionExtended{
			KeyShareExtension: &utls.KeyShareExtension{
				KeyShares: keyShares,
			},
			HybridReuseKey: e.HybridReuseKey,
		}
	case *utls.KeyShareExtension:
		keyShares := make([]utls.KeyShare, len(e.KeyShares))
		for i, ks := range e.KeyShares {
			keyShares[i] = utls.KeyShare{
				Group: ks.Group,
				Data:  append([]byte{}, ks.Data...),
			}
		}
		return &utls.KeyShareExtension{KeyShares: keyShares}
	case *utls.QUICTransportParametersExtension:
		return &utls.QUICTransportParametersExtension{
			TransportParameters: e.TransportParameters,
		}
	case *utls.NPNExtension:
		return &utls.NPNExtension{
			NextProtos: append([]string{}, e.NextProtos...),
		}
	case *utls.ApplicationSettingsExtension:
		return &utls.ApplicationSettingsExtension{
			SupportedProtocols: append([]string{}, e.SupportedProtocols...),
		}
	case *utls.ApplicationSettingsExtensionNew:
		return &utls.ApplicationSettingsExtensionNew{
			SupportedProtocols: append([]string{}, e.SupportedProtocols...),
		}
	case *utls.FakeChannelIDExtension:
		return &utls.FakeChannelIDExtension{
			OldExtensionID: e.OldExtensionID,
		}
	case *utls.GREASEEncryptedClientHelloExtension:
		return &utls.GREASEEncryptedClientHelloExtension{
			CandidateCipherSuites: append([]utls.HPKESymmetricCipherSuite{}, e.CandidateCipherSuites...),
			CandidatePayloadLens:  append([]uint16{}, e.CandidatePayloadLens...),
		}
	case *utls.RenegotiationInfoExtension:
		return &utls.RenegotiationInfoExtension{
			Renegotiation:          e.Renegotiation,
			RenegotiatedConnection: append([]byte{}, e.RenegotiatedConnection...),
		}
	case *utls.UtlsGREASEExtension:
		return &utls.UtlsGREASEExtension{
			Value: e.Value,
			Body:  append([]byte{}, e.Body...),
		}
	case *utls.GenericExtension:
		return &utls.GenericExtension{
			Id:   e.Id,
			Data: append([]byte{}, e.Data...),
		}
	case utls.PreSharedKeyExtension:
		switch psk := e.(type) {
		case *utls.FakePreSharedKeyExtension:
			return deepCloneExtension(psk)
		case *utls.UtlsPreSharedKeyExtension:
			return deepCloneExtension(psk)
		default:
			return deepCloneInterface(e).(utls.TLSExtension)
		}
	default:
		return deepCloneInterface(ext).(utls.TLSExtension)
	}
}

// deepCopyStruct performs deep copying of struct values using reflection.
//
// This function handles the copying of struct fields, including unexported fields
// that cannot be accessed through normal reflection. It uses unsafe operations
// to access unexported fields when necessary.
//
// The function iterates through all fields of the source struct and recursively
// copies each field to the corresponding field in the destination struct.
//
// Parameters:
//   - src: The source struct value to copy from
//   - dst: The destination struct value to copy to
func deepCopyStruct(src, dst reflect.Value) {
	if !src.IsValid() {
		return
	}

	switch src.Kind() {
	case reflect.Struct:
		for i := 0; i < src.NumField(); i++ {
			srcField := src.Field(i)
			dstField := dst.Field(i)

			if !dstField.CanSet() {
				if srcField.CanInterface() || srcField.CanAddr() {
					dstFieldPtr := reflect.NewAt(srcField.Type(),
						unsafe.Pointer(dst.UnsafeAddr()+dst.Type().Field(i).Offset))
					deepCopyValue(srcField, dstFieldPtr.Elem())
				}
			} else {
				deepCopyValue(srcField, dstField)
			}
		}
	default:
		deepCopyValue(src, dst)
	}
}

// deepCopyValue performs deep copying of values of various types using reflection.
//
// This is the core reflection-based copying function that handles different
// value kinds including structs, slices, arrays, maps, pointers, and interfaces.
// It recursively processes nested structures to ensure complete deep copying.
//
// Supported value kinds:
//   - Struct: Delegates to deepCopyStruct for field-by-field copying
//   - Slice: Creates new slice with recursively copied elements
//   - Array: Copies each element in-place
//   - Map: Creates new map with recursively copied keys and values
//   - Pointer: Creates new pointer with recursively copied pointed-to value
//   - Interface: Handles interface values through deepCloneInterface
//   - Chan, Func: Copies reference (cannot deep copy these types)
//   - Basic types: Direct value copying
//
// Parameters:
//   - src: The source value to copy from
//   - dst: The destination value to copy to
func deepCopyValue(src, dst reflect.Value) {
	if !src.IsValid() {
		return
	}

	switch src.Kind() {
	case reflect.Struct:
		deepCopyStruct(src, dst)
	case reflect.Slice:
		if src.IsNil() {
			if dst.CanSet() {
				dst.Set(reflect.Zero(src.Type()))
			}
			return
		}

		newSlice := reflect.MakeSlice(src.Type(), src.Len(), src.Cap())

		for i := 0; i < src.Len(); i++ {
			deepCopyValue(src.Index(i), newSlice.Index(i))
		}

		if dst.CanSet() {
			dst.Set(newSlice)
		}
	case reflect.Array:
		for i := 0; i < src.Len(); i++ {
			deepCopyValue(src.Index(i), dst.Index(i))
		}
	case reflect.Map:
		if src.IsNil() {
			if dst.CanSet() {
				dst.Set(reflect.Zero(src.Type()))
			}
			return
		}

		newMap := reflect.MakeMap(src.Type())

		for _, key := range src.MapKeys() {
			newKey := reflect.New(key.Type()).Elem()
			newVal := reflect.New(src.MapIndex(key).Type()).Elem()

			deepCopyValue(key, newKey)
			deepCopyValue(src.MapIndex(key), newVal)

			newMap.SetMapIndex(newKey, newVal)
		}

		if dst.CanSet() {
			dst.Set(newMap)
		}
	case reflect.Pointer:
		if src.IsNil() {
			if dst.CanSet() {
				dst.Set(reflect.Zero(src.Type()))
			}
			return
		}

		newPtr := reflect.New(src.Type().Elem())

		deepCopyValue(src.Elem(), newPtr.Elem())

		if dst.CanSet() {
			dst.Set(newPtr)
		}
	case reflect.Interface:
		if src.IsNil() {
			if dst.CanSet() {
				dst.Set(reflect.Zero(src.Type()))
			}
			return
		}

		newVal := deepCloneInterface(src.Interface())

		if dst.CanSet() {
			dst.Set(reflect.ValueOf(newVal))
		}
	case reflect.Chan, reflect.Func:
		if dst.CanSet() {
			dst.Set(src)
		}
	default:
		if dst.CanSet() {
			dst.Set(src)
		}
	}
}

// deepCloneInterface creates a deep copy of any interface{} value using reflection.
//
// This function serves as the entry point for reflection-based deep cloning.
// It handles both pointer and non-pointer types, ensuring that the returned
// value is completely independent from the source.
//
// The function process:
//  1. Checks for nil input (returns nil)
//  2. Handles pointer types by creating new pointer and copying pointed-to value
//  3. Handles non-pointer types by creating new value and copying content
//  4. Uses deepCopyValue for the actual recursive copying logic
//
// This function is used as a fallback when specific type handling is not
// available in deepCloneExtension, ensuring that all extension types can
// be cloned even if they are not explicitly supported.
//
// Parameters:
//   - src: The source value to clone (any type)
//
// Returns:
//   - A deeply cloned copy of the source value
//   - Returns nil if source is nil
func deepCloneInterface(src any) any {
	if src == nil {
		return nil
	}

	srcVal := reflect.ValueOf(src)
	srcType := srcVal.Type()

	if srcType.Kind() == reflect.Pointer {
		if srcVal.IsNil() {
			return nil
		}

		dstPtr := reflect.New(srcType.Elem())
		deepCopyValue(srcVal.Elem(), dstPtr.Elem())

		return dstPtr.Interface()
	}

	dst := reflect.New(srcType).Elem()
	deepCopyValue(srcVal, dst)

	return dst.Interface()
}
