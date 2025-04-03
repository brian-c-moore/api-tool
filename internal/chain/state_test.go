package chain // Correct package declaration

import (
	"os" // Import os for env var testing
	"testing"

	"github.com/stretchr/testify/assert"
	// require is not used here, remove if not added later
)

// Rest of the file content remains the same as the original, valid version.
func TestState_SetGet(t *testing.T) {
	s := NewState()
	s.Set("key1", "value1")
	s.Set("key2", "value2")
	val, ok := s.Get("key1"); assert.True(t, ok); assert.Equal(t, "value1", val)
	val, ok = s.Get("key2"); assert.True(t, ok); assert.Equal(t, "value2", val)
	val, ok = s.Get("nonexistent"); assert.False(t, ok); assert.Equal(t, "", val)
	s.Set("key1", "new_value1"); val, ok = s.Get("key1"); assert.True(t, ok); assert.Equal(t, "new_value1", val)
}
func TestState_GetAll(t *testing.T) {
	s := NewState(); s.Set("k1", "v1"); s.Set("k2", "v2"); all := s.GetAll()
	assert.Equal(t, map[string]string{"k1": "v1", "k2": "v2"}, all)
	all["k3"] = "v3"; _, ok := s.Get("k3"); assert.False(t, ok, "Modification to GetAll result should not affect original state")
	sEmpty := NewState(); allEmpty := sEmpty.GetAll(); assert.NotNil(t, allEmpty); assert.Empty(t, allEmpty)
}
func TestState_MergeMap(t *testing.T) {
	s := NewState(); s.Set("a", "1"); s.Set("b", "2")
	mergeData := map[string]string{"b": "new_b", "c": "3"}; s.MergeMap(mergeData)
	expected := map[string]string{"a": "1", "b": "new_b", "c": "3"}; assert.Equal(t, expected, s.GetAll())
	sEmpty := NewState(); sEmpty.MergeMap(mergeData); assert.Equal(t, mergeData, sEmpty.GetAll())
	s.MergeMap(nil); assert.Equal(t, expected, s.GetAll())
	s.MergeMap(map[string]string{}); assert.Equal(t, expected, s.GetAll())
}
func TestState_MergeOSEnv(t *testing.T) {
	s := NewState(); s.Set("PRE_EXISTING", "original_value"); s.Set("ANOTHER", "another_value")
	t.Setenv("TEST_ENV_VAR1", "env_value1"); t.Setenv("PRE_EXISTING", "env_override"); t.Setenv("TEST_ENV_EMPTY", "")
	s.MergeOSEnv(); all := s.GetAll()
	assert.Equal(t, "env_value1", all["TEST_ENV_VAR1"]); assert.Equal(t, "env_override", all["PRE_EXISTING"])
	assert.Equal(t, "another_value", all["ANOTHER"]); assert.Equal(t, "", all["TEST_ENV_EMPTY"])
	_, pathOK := os.LookupEnv("PATH"); if pathOK { assert.NotEmpty(t, all["PATH"], "Expected PATH env var to be merged") }
}