package openapi

// The subset of OpenAPI 3.1 this document uses.
//
// Structs rather than `map[string]any`, for one reason: yaml.v3 emits struct fields in
// declaration order and map keys in sorted order, so a document built from structs has a
// stable shape and a readable diff. A generated file whose key order moved between runs
// would fail its own drift check for no reason and teach everybody to regenerate blindly.

type document struct {
	OpenAPI    string                `yaml:"openapi"`
	Info       info                  `yaml:"info"`
	Servers    []server              `yaml:"servers"`
	Security   []map[string][]string `yaml:"security"`
	Paths      map[string]pathItem   `yaml:"paths"`
	Components components            `yaml:"components"`
}

type info struct {
	Title       string   `yaml:"title"`
	Summary     string   `yaml:"summary"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
	License     *license `yaml:"license,omitempty"`
}

type license struct {
	Name       string `yaml:"name"`
	Identifier string `yaml:"identifier,omitempty"`
}

type server struct {
	URL         string               `yaml:"url"`
	Description string               `yaml:"description,omitempty"`
	Variables   map[string]serverVar `yaml:"variables,omitempty"`
}

type serverVar struct {
	Default     string `yaml:"default"`
	Description string `yaml:"description,omitempty"`
}

type pathItem struct {
	Get    *operation `yaml:"get,omitempty"`
	Post   *operation `yaml:"post,omitempty"`
	Put    *operation `yaml:"put,omitempty"`
	Delete *operation `yaml:"delete,omitempty"`
}

type operation struct {
	OperationID string              `yaml:"operationId"`
	Summary     string              `yaml:"summary"`
	Description string              `yaml:"description,omitempty"`
	Tags        []string            `yaml:"tags,omitempty"`
	Parameters  []parameter         `yaml:"parameters,omitempty"`
	RequestBody *requestBody        `yaml:"requestBody,omitempty"`
	Responses   map[string]response `yaml:"responses"`
}

type parameter struct {
	Name        string  `yaml:"name"`
	In          string  `yaml:"in"`
	Required    bool    `yaml:"required,omitempty"`
	Description string  `yaml:"description,omitempty"`
	Schema      *schema `yaml:"schema,omitempty"`
}

type requestBody struct {
	Required bool                 `yaml:"required,omitempty"`
	Content  map[string]mediaType `yaml:"content"`
}

type response struct {
	Description string               `yaml:"description"`
	Content     map[string]mediaType `yaml:"content,omitempty"`
}

type mediaType struct {
	Schema *schema `yaml:"schema,omitempty"`
}

type components struct {
	Schemas         map[string]schema         `yaml:"schemas"`
	SecuritySchemes map[string]securityScheme `yaml:"securitySchemes"`
}

type securityScheme struct {
	Type        string `yaml:"type"`
	Scheme      string `yaml:"scheme,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// schema is the slice of JSON Schema this document needs.
type schema struct {
	Ref                  string            `yaml:"$ref,omitempty"`
	Type                 string            `yaml:"type,omitempty"`
	Format               string            `yaml:"format,omitempty"`
	Description          string            `yaml:"description,omitempty"`
	Properties           map[string]schema `yaml:"properties,omitempty"`
	Items                *schema           `yaml:"items,omitempty"`
	Required             []string          `yaml:"required,omitempty"`
	Nullable             bool              `yaml:"nullable,omitempty"`
	Enum                 []string          `yaml:"enum,omitempty"`
	AdditionalProperties *schema           `yaml:"additionalProperties,omitempty"`
}
