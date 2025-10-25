/*
 * json_builder.h - Enhanced JSON Parser and Builder Library
 *
 * Author: Philip R. Simonson (aka 5n4k3)
 * Started : 10/09/2025
 * Finished: 10/22/2025
 * 
 ***********************************************************************
 * Features:
 * - Unlimited nesting depth (dynamic stack)
 * - Pretty-printing support
 * - Streaming support
 * - Better error messages
 * 
 * Version: 2.0
 * 
 * License: MIT License
 * Copyright 2025 Philip R. Simonson
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef JSON_BUILDER_H
#define JSON_BUILDER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * TYPES AND CONSTANTS
 * ========================================================================== */

typedef enum {
    JSON_INSERT_BEFORE = 0,
    JSON_INSERT_AFTER  = 1
} json_insert_mode_t;

typedef enum {
    JSON_UNDEFINED = 0,
    JSON_OBJECT = 1,
    JSON_ARRAY = 2,
    JSON_STRING = 3,
    JSON_PRIMITIVE = 4
} json_type_t;

typedef enum {
    JSON_VALUE_RAW = 0,      /* Raw JSON string */
    JSON_VALUE_STRING = 1,   /* String value (will be escaped) */
    JSON_VALUE_INT = 2,      /* Integer value */
    JSON_VALUE_DOUBLE = 3,   /* Double value */
    JSON_VALUE_BOOL = 4,     /* Boolean value */
    JSON_VALUE_NULL = 5      /* Null value */
} json_value_type_t;

typedef enum {
    JSON_ERROR_NONE = 0,
    JSON_ERROR_NOMEM = -1,
    JSON_ERROR_INVAL = -2,
    JSON_ERROR_PART = -3,
    JSON_ERROR_BUFFER_FULL = -4,
    JSON_ERROR_MAX_DEPTH = -5
} json_error_t;

typedef struct {
    json_value_type_t type;
    union {
        const char *str_val;
        int64_t int_val;
        double double_val;
        bool bool_val;
    } data;
} json_value_t;

typedef struct {
    json_type_t type;
    int start;
    int end;
    int size;
    int parent;
} json_token_t;

typedef struct {
    unsigned int pos;
    unsigned int toknext;
    int toksuper;
} json_parser_t;

/* Dynamic stack for unlimited nesting */
typedef struct {
    json_type_t *data;
    size_t size;
    size_t capacity;
} json_stack_t;

/* Pretty-print options */
typedef struct {
    bool enabled;
    int indent_size;
    char indent_char;
    bool space_after_colon;
    bool space_after_comma;
    bool trailing_newline;
} json_format_t;

typedef struct {
    char *buffer;
    size_t size;
    size_t pos;
    size_t depth;
    json_stack_t stack;
    bool needs_comma;
    json_format_t format;
    bool owns_stack;
} json_builder_t;

/* Streaming parser state */
typedef struct {
    json_parser_t parser;
    json_token_t *tokens;
    size_t max_tokens;
    size_t tokens_used;
    char *input_buffer;
    size_t buffer_size;
    size_t buffer_used;
    bool complete;
} json_stream_parser_t;

/* ============================================================================
 * PARSER API
 * ========================================================================== */

void json_parser_init(json_parser_t *parser);
int json_parse(json_parser_t *parser, const char *js, size_t len,
               json_token_t *tokens, unsigned int num_tokens);

/* Helper functions */
int json_token_strcmp(const char *js, const json_token_t *tok, const char *s);
int json_token_strlen(const json_token_t *tok);
int json_token_strcpy(const char *js, const json_token_t *tok,
                      char *buf, size_t bufsize);
int json_token_to_int(const char *js, const json_token_t *tok, int *out);
int json_token_to_int64(const char *js, const json_token_t *tok, int64_t *out);
int json_token_to_double(const char *js, const json_token_t *tok, double *out);
bool json_token_is_true(const char *js, const json_token_t *tok);
bool json_token_is_false(const char *js, const json_token_t *tok);
bool json_token_is_null(const char *js, const json_token_t *tok);

/* ============================================================================
 * STREAMING PARSER API
 * ========================================================================== */

json_error_t json_stream_parser_init(json_stream_parser_t *stream,
                                     json_token_t *tokens, size_t max_tokens,
                                     char *buffer, size_t buffer_size);
json_error_t json_stream_parser_feed(json_stream_parser_t *stream,
                                     const char *data, size_t len);
bool json_stream_parser_is_complete(json_stream_parser_t *stream);
void json_stream_parser_reset(json_stream_parser_t *stream);

/* ============================================================================
 * BUILDER API
 * ========================================================================== */

/* Initialization */
json_error_t json_builder_init(json_builder_t *builder, char *buffer, size_t size);
json_error_t json_builder_init_dynamic(json_builder_t *builder, char *buffer, 
                                       size_t size, size_t initial_stack_capacity);
void json_builder_free(json_builder_t *builder);

/* Format control */
void json_builder_set_format(json_builder_t *builder, const json_format_t *format);
void json_builder_enable_pretty_print(json_builder_t *builder, int indent_size);
void json_builder_disable_pretty_print(json_builder_t *builder);

/* Container functions */
json_error_t json_builder_object_begin(json_builder_t *builder);
json_error_t json_builder_object_end(json_builder_t *builder);
json_error_t json_builder_array_begin(json_builder_t *builder);
json_error_t json_builder_array_end(json_builder_t *builder);

/* Value functions */
json_error_t json_builder_key(json_builder_t *builder, const char *key);
json_error_t json_builder_string(json_builder_t *builder, const char *value);
json_error_t json_builder_int(json_builder_t *builder, int64_t value);
json_error_t json_builder_double(json_builder_t *builder, double value);
json_error_t json_builder_bool(json_builder_t *builder, bool value);
json_error_t json_builder_null(json_builder_t *builder);

/* Raw value (no escaping) */
json_error_t json_builder_raw(json_builder_t *builder, const char *json);

/* Retrieval */
const char *json_builder_get_string(json_builder_t *builder);
size_t json_builder_get_length(json_builder_t *builder);

/* Reset for reuse */
void json_builder_reset(json_builder_t *builder);

/* ============================================================================
 * PRETTY PRINTER API
 * ========================================================================== */

json_error_t json_pretty_print(const char *input, char *output, size_t output_size,
                               int indent_size);
json_error_t json_minify(const char *input, char *output, size_t output_size);

/* Default: insert AFTER the referenced index (e.g., "user.array[3]"). */
json_error_t json_insert_path(const char *input,
                              const char *path,
                              const char *new_item_json,
                              char *output,
                              size_t output_size);

/* Explicit mode (BEFORE/AFTER). Output uses compact formatting by default. */
json_error_t json_insert_path_ex(const char *input,
                                 const char *path,
                                 const char *new_item_json,
                                 json_insert_mode_t mode,
                                 char *output,
                                 size_t output_size);

/* Set value at path. Creates intermediate objects/arrays as needed. */
json_error_t json_set_path_value(const char *input,
                                 const char *path,
                                 const json_value_t *value,
                                 char *output,
                                 size_t output_size);

#ifdef __cplusplus
}
#endif

#endif /* JSON_BUILDER_H */

/* ============================================================================
 * IMPLEMENTATION
 * ========================================================================== */

#ifdef JSON_IMPLEMENTATION

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <ctype.h>

#ifndef JSON_MALLOC
#define JSON_MALLOC malloc
#endif

#ifndef JSON_FREE
#define JSON_FREE free
#endif

#ifndef JSON_REALLOC
#define JSON_REALLOC realloc
#endif

/* ============================================================================
 * DYNAMIC STACK IMPLEMENTATION
 * ========================================================================== */

static json_error_t json_stack_init(json_stack_t *stack, size_t initial_capacity) {
    stack->data = (json_type_t *)JSON_MALLOC(initial_capacity * sizeof(json_type_t));
    if (stack->data == NULL) {
        return JSON_ERROR_NOMEM;
    }
    stack->size = 0;
    stack->capacity = initial_capacity;
    return JSON_ERROR_NONE;
}

static void json_stack_free(json_stack_t *stack) {
    if (stack->data != NULL) {
        JSON_FREE(stack->data);
        stack->data = NULL;
    }
    stack->size = 0;
    stack->capacity = 0;
}

static json_error_t json_stack_push(json_stack_t *stack, json_type_t type) {
    if (stack->size >= stack->capacity) {
        size_t new_capacity = stack->capacity * 2;
        if (new_capacity < 16) new_capacity = 16;
        
        json_type_t *new_data = (json_type_t *)JSON_REALLOC(
            stack->data, new_capacity * sizeof(json_type_t));
        
        if (new_data == NULL) {
            return JSON_ERROR_NOMEM;
        }
        
        stack->data = new_data;
        stack->capacity = new_capacity;
    }
    
    stack->data[stack->size++] = type;
    return JSON_ERROR_NONE;
}

static json_error_t json_stack_pop(json_stack_t *stack, json_type_t *type) {
    if (stack->size == 0) {
        return JSON_ERROR_INVAL;
    }
    
    if (type != NULL) {
        *type = stack->data[stack->size - 1];
    }
    stack->size--;
    return JSON_ERROR_NONE;
}

static json_type_t json_stack_peek(const json_stack_t *stack) {
    if (stack->size == 0) {
        return JSON_UNDEFINED;
    }
    return stack->data[stack->size - 1];
}

/* ============================================================================
 * PARSER IMPLEMENTATION (Same as before)
 * ========================================================================== */

static json_token_t *json_alloc_token(json_parser_t *parser,
                                     json_token_t *tokens,
                                     unsigned int num_tokens) {
    json_token_t *tok;
    if (parser->toknext >= num_tokens) {
        return NULL;
    }
    tok = &tokens[parser->toknext++];
    tok->start = tok->end = -1;
    tok->size = 0;
    tok->parent = -1;
    return tok;
}

static void json_fill_token(json_token_t *token, json_type_t type,
                           int start, int end) {
    token->type = type;
    token->start = start;
    token->end = end;
    token->size = 0;
}

static int json_parse_string(json_parser_t *parser, const char *js,
                            size_t len, json_token_t *tokens,
                            unsigned int num_tokens) {
    json_token_t *token;
    int start = parser->pos;
    
    parser->pos++;
    
    for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
        char c = js[parser->pos];
        
        if (c == '\"') {
            if (tokens == NULL) {
                parser->pos++;
                return 0;
            }
            token = json_alloc_token(parser, tokens, num_tokens);
            if (token == NULL) {
                parser->pos = start;
                return JSON_ERROR_NOMEM;
            }
            json_fill_token(token, JSON_STRING, start + 1, parser->pos);
            token->parent = parser->toksuper;
            parser->pos++;
            return 0;
        }
        
        if (c == '\\' && parser->pos + 1 < len) {
            parser->pos++;
            switch (js[parser->pos]) {
                case '\"':
                case '/':
                case '\\':
                case 'b':
                case 'f':
                case 'r':
                case 'n':
                case 't':
                    break;
                case 'u':
                    parser->pos++;
                    for (int i = 0; i < 4 && parser->pos < len && js[parser->pos] != '\0'; i++) {
                        if (!((js[parser->pos] >= '0' && js[parser->pos] <= '9') ||
                              (js[parser->pos] >= 'A' && js[parser->pos] <= 'F') ||
                              (js[parser->pos] >= 'a' && js[parser->pos] <= 'f'))) {
                            parser->pos = start;
                            return JSON_ERROR_INVAL;
                        }
                        parser->pos++;
                    }
                    parser->pos--;
                    break;
                default:
                    parser->pos = start;
                    return JSON_ERROR_INVAL;
            }
        }
    }
    parser->pos = start;
    return JSON_ERROR_PART;
}

static int json_parse_primitive(json_parser_t *parser, const char *js,
                                size_t len, json_token_t *tokens,
                                unsigned int num_tokens) {
    json_token_t *token;
    int start = parser->pos;
    
    for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
        switch (js[parser->pos]) {
            case ':':
            case '\t':
            case '\r':
            case '\n':
            case ' ':
            case ',':
            case ']':
            case '}':
                goto found;
            default:
                break;
        }
        if (js[parser->pos] < 32 || js[parser->pos] >= 127) {
            parser->pos = start;
            return JSON_ERROR_INVAL;
        }
    }
    
found:
    if (tokens == NULL) {
        parser->pos--;
        return 0;
    }
    token = json_alloc_token(parser, tokens, num_tokens);
    if (token == NULL) {
        parser->pos = start;
        return JSON_ERROR_NOMEM;
    }
    json_fill_token(token, JSON_PRIMITIVE, start, parser->pos);
    token->parent = parser->toksuper;
    parser->pos--;
    return 0;
}

void json_parser_init(json_parser_t *parser) {
    parser->pos = 0;
    parser->toknext = 0;
    parser->toksuper = -1;
}

int json_parse(json_parser_t *parser, const char *js, size_t len,
               json_token_t *tokens, unsigned int num_tokens) {
    int r;
    int i;
    json_token_t *token;
    int count = parser->toknext;
    
    for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
        char c = js[parser->pos];
        json_type_t type;
        
        switch (c) {
            case '{':
            case '[':
                count++;
                if (tokens == NULL) {
                    break;
                }
                token = json_alloc_token(parser, tokens, num_tokens);
                if (token == NULL) {
                    return JSON_ERROR_NOMEM;
                }
                if (parser->toksuper != -1) {
                    json_token_t *t = &tokens[parser->toksuper];
                    t->size++;
                    token->parent = parser->toksuper;
                }
                token->type = (c == '{' ? JSON_OBJECT : JSON_ARRAY);
                token->start = parser->pos;
                parser->toksuper = parser->toknext - 1;
                break;
                
            case '}':
            case ']':
                if (tokens == NULL) {
                    break;
                }
                type = (c == '}' ? JSON_OBJECT : JSON_ARRAY);
                for (i = parser->toknext - 1; i >= 0; i--) {
                    token = &tokens[i];
                    if (token->start != -1 && token->end == -1) {
                        if (token->type != type) {
                            return JSON_ERROR_INVAL;
                        }
                        parser->toksuper = token->parent;
                        token->end = parser->pos + 1;
                        break;
                    }
                }
                if (i == -1) {
                    return JSON_ERROR_INVAL;
                }
                for (; i >= 0; i--) {
                    token = &tokens[i];
                    if (token->start != -1 && token->end == -1) {
                        parser->toksuper = i;
                        break;
                    }
                }
                break;
                
            case '\"':
                r = json_parse_string(parser, js, len, tokens, num_tokens);
                if (r < 0) {
                    return r;
                }
                count++;
                if (parser->toksuper != -1 && tokens != NULL) {
                    tokens[parser->toksuper].size++;
                }
                break;
                
            case '\t':
            case '\r':
            case '\n':
            case ' ':
                break;
                
            case ':':
                parser->toksuper = parser->toknext - 1;
                break;
                
            case ',':
                if (tokens != NULL && parser->toksuper != -1 &&
                    tokens[parser->toksuper].type != JSON_ARRAY &&
                    tokens[parser->toksuper].type != JSON_OBJECT) {
                    for (i = parser->toknext - 1; i >= 0; i--) {
                        if (tokens[i].type == JSON_ARRAY || tokens[i].type == JSON_OBJECT) {
                            if (tokens[i].start != -1 && tokens[i].end == -1) {
                                parser->toksuper = i;
                                break;
                            }
                        }
                    }
                }
                break;
                
            case '-':
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            case 't':
            case 'f':
            case 'n':
                // Parse primitives
                r = json_parse_primitive(parser, js, len, tokens, num_tokens);
                if (r < 0) {
                    return r;
                }
                count++;
                if (parser->toksuper != -1 && tokens != NULL) {
                    tokens[parser->toksuper].size++;
                }
                break;
                
            default:
                return JSON_ERROR_INVAL;
        }
    }
    
    if (tokens != NULL) {
        for (i = parser->toknext - 1; i >= 0; i--) {
            if (tokens[i].start != -1 && tokens[i].end == -1) {
                return JSON_ERROR_PART;
            }
        }
    }
    
    return count;
}

/* Helper functions implementation */
int json_token_strcmp(const char *js, const json_token_t *tok, const char *s) {
    if (tok->type != JSON_STRING) {
        return -1;
    }
    
    int len = tok->end - tok->start;
    int slen = strlen(s);
    
    if (len != slen) {
        return len - slen;
    }
    
    return strncmp(js + tok->start, s, len);
}

int json_token_strlen(const json_token_t *tok) {
    return tok->end - tok->start;
}

int json_token_strcpy(const char *js, const json_token_t *tok,
                      char *buf, size_t bufsize) {
    if (tok->type != JSON_STRING && tok->type != JSON_PRIMITIVE) {
        return -1;
    }
    
    int len = tok->end - tok->start;
    if (len >= (int)bufsize) {
        return -1;
    }
    
    memcpy(buf, js + tok->start, len);
    buf[len] = '\0';
    return len;
}

int json_token_to_int(const char *js, const json_token_t *tok, int *out) {
    if (tok->type != JSON_PRIMITIVE) {
        return -1;
    }
    
    char buf[32];
    int len = tok->end - tok->start;
    if (len >= (int)sizeof(buf)) {
        return -1;
    }
    
    memcpy(buf, js + tok->start, len);
    buf[len] = '\0';
    
    char *endptr;
    long val = strtol(buf, &endptr, 10);
    if (endptr != buf + len) {
        return -1;
    }
    
    *out = (int)val;
    return 0;
}

int json_token_to_int64(const char *js, const json_token_t *tok, int64_t *out) {
    if (tok->type != JSON_PRIMITIVE) {
        return -1;
    }
    
    char buf[32];
    int len = tok->end - tok->start;
    if (len >= (int)sizeof(buf)) {
        return -1;
    }
    
    memcpy(buf, js + tok->start, len);
    buf[len] = '\0';
    
    char *endptr;
    long long val = strtoll(buf, &endptr, 10);
    if (endptr != buf + len) {
        return -1;
    }
    
    *out = (int64_t)val;
    return 0;
}

int json_token_to_double(const char *js, const json_token_t *tok, double *out) {
    if (tok->type != JSON_PRIMITIVE) {
        return -1;
    }
    
    char buf[64];
    int len = tok->end - tok->start;
    if (len >= (int)sizeof(buf)) {
        return -1;
    }
    
    memcpy(buf, js + tok->start, len);
    buf[len] = '\0';
    
    char *endptr;
    double val = strtod(buf, &endptr);
    if (endptr != buf + len) {
        return -1;
    }
    
    *out = val;
    return 0;
}

bool json_token_is_true(const char *js, const json_token_t *tok) {
    if (tok->type != JSON_PRIMITIVE) {
        return false;
    }
    return (tok->end - tok->start == 4 && strncmp(js + tok->start, "true", 4) == 0);
}

bool json_token_is_false(const char *js, const json_token_t *tok) {
    if (tok->type != JSON_PRIMITIVE) {
        return false;
    }
    return (tok->end - tok->start == 5 && strncmp(js + tok->start, "false", 5) == 0);
}

bool json_token_is_null(const char *js, const json_token_t *tok) {
    if (tok->type != JSON_PRIMITIVE) {
        return false;
    }
    return (tok->end - tok->start == 4 && strncmp(js + tok->start, "null", 4) == 0);
}

/* ============================================================================
 * STREAMING PARSER IMPLEMENTATION
 * ========================================================================== */

json_error_t json_stream_parser_init(json_stream_parser_t *stream,
                                     json_token_t *tokens, size_t max_tokens,
                                     char *buffer, size_t buffer_size) {
    if (stream == NULL || tokens == NULL || buffer == NULL) {
        return JSON_ERROR_INVAL;
    }
    
    json_parser_init(&stream->parser);
    stream->tokens = tokens;
    stream->max_tokens = max_tokens;
    stream->tokens_used = 0;
    stream->input_buffer = buffer;
    stream->buffer_size = buffer_size;
    stream->buffer_used = 0;
    stream->complete = false;
    
    return JSON_ERROR_NONE;
}

json_error_t json_stream_parser_feed(json_stream_parser_t *stream,
                                     const char *data, size_t len) {
    if (stream == NULL || data == NULL) {
        return JSON_ERROR_INVAL;
    }
    
    if (stream->complete) {
        return JSON_ERROR_INVAL;
    }
    
    // Check if we have enough buffer space
    if (stream->buffer_used + len > stream->buffer_size) {
        return JSON_ERROR_BUFFER_FULL;
    }
    
    // Append data to buffer
    memcpy(stream->input_buffer + stream->buffer_used, data, len);
    stream->buffer_used += len;
    
    // Try to parse
    int result = json_parse(&stream->parser, stream->input_buffer, 
                           stream->buffer_used, stream->tokens, 
                           stream->max_tokens);
    
    if (result > 0) {
        stream->tokens_used = result;
        stream->complete = true;
        return JSON_ERROR_NONE;
    } else if (result == JSON_ERROR_PART) {
        // Need more data
        return JSON_ERROR_NONE;
    } else {
        // Parse error
        return (json_error_t)result;
    }
}

bool json_stream_parser_is_complete(json_stream_parser_t *stream) {
    return stream != NULL && stream->complete;
}

void json_stream_parser_reset(json_stream_parser_t *stream) {
    if (stream != NULL) {
        json_parser_init(&stream->parser);
        stream->tokens_used = 0;
        stream->buffer_used = 0;
        stream->complete = false;
    }
}

/* ============================================================================
 * BUILDER IMPLEMENTATION
 * ========================================================================== */

static json_error_t json_builder_append(json_builder_t *builder, 
                                        const char *str, size_t len) {
    if (builder->pos + len >= builder->size) {
        return JSON_ERROR_BUFFER_FULL;
    }
    
    memcpy(builder->buffer + builder->pos, str, len);
    builder->pos += len;
    builder->buffer[builder->pos] = '\0';
    
    return JSON_ERROR_NONE;
}

static json_error_t json_builder_append_char(json_builder_t *builder, char c) {
    if (builder->pos + 1 >= builder->size) {
        return JSON_ERROR_BUFFER_FULL;
    }
    
    builder->buffer[builder->pos++] = c;
    builder->buffer[builder->pos] = '\0';
    
    return JSON_ERROR_NONE;
}

static json_error_t json_builder_append_indent(json_builder_t *builder) {
    if (!builder->format.enabled) {
        return JSON_ERROR_NONE;
    }
    
    json_error_t err = json_builder_append_char(builder, '\n');
    if (err != JSON_ERROR_NONE) return err;
    
    for (size_t i = 0; i < builder->depth; i++) {
        for (int j = 0; j < builder->format.indent_size; j++) {
            err = json_builder_append_char(builder, builder->format.indent_char);
            if (err != JSON_ERROR_NONE) return err;
        }
    }
    
    return JSON_ERROR_NONE;
}

static json_error_t json_builder_append_comma(json_builder_t *builder) {
    if (builder->needs_comma) {
        json_error_t err = json_builder_append_char(builder, ',');
        if (err != JSON_ERROR_NONE) return err;
        
        if (builder->format.enabled && builder->format.space_after_comma) {
            err = json_builder_append_char(builder, ' ');
            if (err != JSON_ERROR_NONE) return err;
        }
        
        builder->needs_comma = false;
    }
    return JSON_ERROR_NONE;
}

static json_error_t json_builder_escape_string(json_builder_t *builder, 
                                               const char *str) {
    json_error_t err;
    
    err = json_builder_append_char(builder, '\"');
    if (err != JSON_ERROR_NONE) return err;
    
    for (const char *p = str; *p != '\0'; p++) {
        switch (*p) {
            case '\"':
                err = json_builder_append(builder, "\\\"", 2);
                break;
            case '\\':
                err = json_builder_append(builder, "\\\\", 2);
                break;
            case '\b':
                err = json_builder_append(builder, "\\b", 2);
                break;
            case '\f':
                err = json_builder_append(builder, "\\f", 2);
                break;
            case '\n':
                err = json_builder_append(builder, "\\n", 2);
                break;
            case '\r':
                err = json_builder_append(builder, "\\r", 2);
                break;
            case '\t':
                err = json_builder_append(builder, "\\t", 2);
                break;
            default:
                if ((unsigned char)*p < 32) {
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)*p);
                    err = json_builder_append(builder, buf, 6);
                } else {
                    err = json_builder_append_char(builder, *p);
                }
                break;
        }
        
        if (err != JSON_ERROR_NONE) return err;
    }
    
    err = json_builder_append_char(builder, '\"');
    return err;
}

json_error_t json_builder_init(json_builder_t *builder, char *buffer, size_t size) {
    return json_builder_init_dynamic(builder, buffer, size, 32);
}

json_error_t json_builder_init_dynamic(json_builder_t *builder, char *buffer, 
                                       size_t size, size_t initial_stack_capacity) {
    if (builder == NULL || buffer == NULL || size == 0) {
        return JSON_ERROR_INVAL;
    }
    
    builder->buffer = buffer;
    builder->size = size;
    builder->pos = 0;
    builder->depth = 0;
    builder->needs_comma = false;
    builder->owns_stack = true;
    
    // Initialize format with defaults (compact)
    builder->format.enabled = false;
    builder->format.indent_size = 2;
    builder->format.indent_char = ' ';
    builder->format.space_after_colon = false;
    builder->format.space_after_comma = false;
    builder->format.trailing_newline = false;
    
    buffer[0] = '\0';
    
    json_error_t err = json_stack_init(&builder->stack, initial_stack_capacity);
    if (err != JSON_ERROR_NONE) {
        return err;
    }
    
    return JSON_ERROR_NONE;
}

void json_builder_free(json_builder_t *builder) {
    if (builder != NULL && builder->owns_stack) {
        json_stack_free(&builder->stack);
    }
}

void json_builder_set_format(json_builder_t *builder, const json_format_t *format) {
    if (builder != NULL && format != NULL) {
        builder->format = *format;
    }
}

void json_builder_enable_pretty_print(json_builder_t *builder, int indent_size) {
    if (builder != NULL) {
        builder->format.enabled = true;
        builder->format.indent_size = indent_size > 0 ? indent_size : 2;
        builder->format.indent_char = ' ';
        builder->format.space_after_colon = true;
        builder->format.space_after_comma = false;
        builder->format.trailing_newline = true;
    }
}

void json_builder_disable_pretty_print(json_builder_t *builder) {
    if (builder != NULL) {
        builder->format.enabled = false;
        builder->format.space_after_colon = false;
        builder->format.space_after_comma = false;
        builder->format.trailing_newline = false;
    }
}

json_error_t json_builder_object_begin(json_builder_t *builder) {
    if (builder == NULL) {
        return JSON_ERROR_INVAL;
    }
    
    json_error_t err;
    
    err = json_builder_append_comma(builder);
    if (err != JSON_ERROR_NONE) return err;
    
    if (builder->format.enabled && builder->stack.size > 0) {
        err = json_builder_append_indent(builder);
        if (err != JSON_ERROR_NONE) return err;
    }
    
    err = json_builder_append_char(builder, '{');
    if (err != JSON_ERROR_NONE) return err;
    
    err = json_stack_push(&builder->stack, JSON_OBJECT);
    if (err != JSON_ERROR_NONE) return err;
    
    builder->depth++;
    builder->needs_comma = false;
    
    return JSON_ERROR_NONE;
}

json_error_t json_builder_object_end(json_builder_t *builder) {
    if (builder == NULL) {
        return JSON_ERROR_INVAL;
    }
    
    json_type_t type;
    json_error_t err = json_stack_pop(&builder->stack, &type);
    if (err != JSON_ERROR_NONE) return err;
    
    if (type != JSON_OBJECT) {
        return JSON_ERROR_INVAL;
    }
    
    builder->depth--;
    
    if (builder->format.enabled && builder->needs_comma) {
        err = json_builder_append_indent(builder);
        if (err != JSON_ERROR_NONE) return err;
    }
    
    err = json_builder_append_char(builder, '}');
    if (err != JSON_ERROR_NONE) return err;
    
    builder->needs_comma = true;
    
    return JSON_ERROR_NONE;
}

json_error_t json_builder_array_begin(json_builder_t *builder) {
    if (builder == NULL) {
        return JSON_ERROR_INVAL;
    }
    
    json_error_t err;
    
    err = json_builder_append_comma(builder);
    if (err != JSON_ERROR_NONE) return err;
    
    if (builder->format.enabled && builder->stack.size > 0) {
        err = json_builder_append_indent(builder);
        if (err != JSON_ERROR_NONE) return err;
    }
    
    err = json_builder_append_char(builder, '[');
    if (err != JSON_ERROR_NONE) return err;
    
    err = json_stack_push(&builder->stack, JSON_ARRAY);
    if (err != JSON_ERROR_NONE) return err;
    
    builder->depth++;
    builder->needs_comma = false;
    
    return JSON_ERROR_NONE;
}

json_error_t json_builder_array_end(json_builder_t *builder) {
    if (builder == NULL) {
        return JSON_ERROR_INVAL;
    }
    
    json_type_t type;
    json_error_t err = json_stack_pop(&builder->stack, &type);
    if (err != JSON_ERROR_NONE) return err;
    
    if (type != JSON_ARRAY) {
        return JSON_ERROR_INVAL;
    }
    
    builder->depth--;
    
    if (builder->format.enabled && builder->needs_comma) {
        err = json_builder_append_indent(builder);
        if (err != JSON_ERROR_NONE) return err;
    }
    
    err = json_builder_append_char(builder, ']');
    if (err != JSON_ERROR_NONE) return err;
    
    builder->needs_comma = true;
    
    return JSON_ERROR_NONE;
}

json_error_t json_builder_key(json_builder_t *builder, const char *key) {
    if (builder == NULL || key == NULL) {
        return JSON_ERROR_INVAL;
    }
    
    json_type_t current = json_stack_peek(&builder->stack);
    if (current != JSON_OBJECT) {
        return JSON_ERROR_INVAL;
    }
    
    json_error_t err;
    
    err = json_builder_append_comma(builder);
    if (err != JSON_ERROR_NONE) return err;
    
    if (builder->format.enabled) {
        err = json_builder_append_indent(builder);
        if (err != JSON_ERROR_NONE) return err;
    }
    
    err = json_builder_escape_string(builder, key);
    if (err != JSON_ERROR_NONE) return err;
    
    err = json_builder_append_char(builder, ':');
    if (err != JSON_ERROR_NONE) return err;
    
    if (builder->format.enabled && builder->format.space_after_colon) {
        err = json_builder_append_char(builder, ' ');
        if (err != JSON_ERROR_NONE) return err;
    }
    
    return JSON_ERROR_NONE;
}

json_error_t json_builder_string(json_builder_t *builder, const char *value) {
    if (builder == NULL || value == NULL) {
        return JSON_ERROR_INVAL;
    }
    
    json_type_t current = json_stack_peek(&builder->stack);
    
    json_error_t err;
    
    if (current == JSON_ARRAY) {
        err = json_builder_append_comma(builder);
        if (err != JSON_ERROR_NONE) return err;
        
        if (builder->format.enabled) {
            err = json_builder_append_indent(builder);
            if (err != JSON_ERROR_NONE) return err;
        }
    }
    
    err = json_builder_escape_string(builder, value);
    if (err != JSON_ERROR_NONE) return err;
    
    builder->needs_comma = true;
    
    return JSON_ERROR_NONE;
}

json_error_t json_builder_int(json_builder_t *builder, int64_t value) {
    if (builder == NULL) {
        return JSON_ERROR_INVAL;
    }
    
    json_type_t current = json_stack_peek(&builder->stack);
    
    json_error_t err;
    
    if (current == JSON_ARRAY) {
        err = json_builder_append_comma(builder);
        if (err != JSON_ERROR_NONE) return err;
        
        if (builder->format.enabled) {
            err = json_builder_append_indent(builder);
            if (err != JSON_ERROR_NONE) return err;
        }
    }
    
    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%lld", (long long)value);
    
    err = json_builder_append(builder, buf, len);
    if (err != JSON_ERROR_NONE) return err;
    
    builder->needs_comma = true;
    
    return JSON_ERROR_NONE;
}

json_error_t json_builder_double(json_builder_t *builder, double value) {
    if (builder == NULL) {
        return JSON_ERROR_INVAL;
    }
    
    // Handle special values
    if (isnan(value) || isinf(value)) {
        return json_builder_null(builder);
    }
    
    json_type_t current = json_stack_peek(&builder->stack);
    
    json_error_t err;
    
    if (current == JSON_ARRAY) {
        err = json_builder_append_comma(builder);
        if (err != JSON_ERROR_NONE) return err;
        
        if (builder->format.enabled) {
            err = json_builder_append_indent(builder);
            if (err != JSON_ERROR_NONE) return err;
        }
    }
    
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%.17g", value);
    
    // Ensure it looks like a number (add .0 if needed)
    bool has_dot = false;
    bool has_exp = false;
    for (int i = 0; i < len; i++) {
        if (buf[i] == '.') has_dot = true;
        if (buf[i] == 'e' || buf[i] == 'E') has_exp = true;
    }
    
    if (!has_dot && !has_exp) {
        buf[len++] = '.';
        buf[len++] = '0';
        buf[len] = '\0';
    }
    
    err = json_builder_append(builder, buf, len);
    if (err != JSON_ERROR_NONE) return err;
    
    builder->needs_comma = true;
    
    return JSON_ERROR_NONE;
}

json_error_t json_builder_bool(json_builder_t *builder, bool value) {
    if (builder == NULL) {
        return JSON_ERROR_INVAL;
    }
    
    json_type_t current = json_stack_peek(&builder->stack);
    
    json_error_t err;
    
    if (current == JSON_ARRAY) {
        err = json_builder_append_comma(builder);
        if (err != JSON_ERROR_NONE) return err;
        
        if (builder->format.enabled) {
            err = json_builder_append_indent(builder);
            if (err != JSON_ERROR_NONE) return err;
        }
    }
    
    const char *str = value ? "true" : "false";
    err = json_builder_append(builder, str, strlen(str));
    if (err != JSON_ERROR_NONE) return err;
    
    builder->needs_comma = true;
    
    return JSON_ERROR_NONE;
}

json_error_t json_builder_null(json_builder_t *builder) {
    if (builder == NULL) {
        return JSON_ERROR_INVAL;
    }
    
    json_type_t current = json_stack_peek(&builder->stack);
    
    json_error_t err;
    
    if (current == JSON_ARRAY) {
        err = json_builder_append_comma(builder);
        if (err != JSON_ERROR_NONE) return err;
        
        if (builder->format.enabled) {
            err = json_builder_append_indent(builder);
            if (err != JSON_ERROR_NONE) return err;
        }
    }
    
    err = json_builder_append(builder, "null", 4);
    if (err != JSON_ERROR_NONE) return err;
    
    builder->needs_comma = true;
    
    return JSON_ERROR_NONE;
}

json_error_t json_builder_raw(json_builder_t *builder, const char *json) {
    if (builder == NULL || json == NULL) {
        return JSON_ERROR_INVAL;
    }
    
    json_type_t current = json_stack_peek(&builder->stack);
    
    json_error_t err;
    
    if (current == JSON_ARRAY) {
        err = json_builder_append_comma(builder);
        if (err != JSON_ERROR_NONE) return err;
        
        if (builder->format.enabled) {
            err = json_builder_append_indent(builder);
            if (err != JSON_ERROR_NONE) return err;
        }
    }
    
    err = json_builder_append(builder, json, strlen(json));
    if (err != JSON_ERROR_NONE) return err;
    
    builder->needs_comma = true;
    
    return JSON_ERROR_NONE;
}

const char *json_builder_get_string(json_builder_t *builder) {
    if (builder == NULL) {
        return NULL;
    }
    
    // Add trailing newline if pretty-printing
    if (builder->format.enabled && builder->format.trailing_newline && 
        builder->stack.size == 0 && builder->pos > 0) {
        if (builder->buffer[builder->pos - 1] != '\n') {
            json_builder_append_char(builder, '\n');
        }
    }
    
    return builder->buffer;
}

size_t json_builder_get_length(json_builder_t *builder) {
    if (builder == NULL) {
        return 0;
    }
    return builder->pos;
}

void json_builder_reset(json_builder_t *builder) {
    if (builder != NULL) {
        builder->pos = 0;
        builder->depth = 0;
        builder->needs_comma = false;
        builder->stack.size = 0;
        if (builder->buffer != NULL) {
            builder->buffer[0] = '\0';
        }
    }
}

/* ============================================================================
 * PRETTY PRINTER IMPLEMENTATION
 * ========================================================================== */

json_error_t json_pretty_print(const char *input, char *output, 
                               size_t output_size, int indent_size) {
    if (input == NULL || output == NULL || output_size == 0) {
        return JSON_ERROR_INVAL;
    }
    
    // Parse input
    json_parser_t parser;
    json_token_t *tokens = (json_token_t *)JSON_MALLOC(1000 * sizeof(json_token_t));
    if (tokens == NULL) {
        return JSON_ERROR_NOMEM;
    }
    
    json_parser_init(&parser);
    int num_tokens = json_parse(&parser, input, strlen(input), tokens, 1000);
    
    if (num_tokens < 0) {
        JSON_FREE(tokens);
        return (json_error_t)num_tokens;
    }
    
    // Rebuild with pretty-printing
    json_builder_t builder;
    json_error_t err = json_builder_init(&builder, output, output_size);
    if (err != JSON_ERROR_NONE) {
        JSON_FREE(tokens);
        return err;
    }
    
    json_builder_enable_pretty_print(&builder, indent_size);
    
    // Recursive function to rebuild
    int token_index = 0;
    
    void rebuild_value(int *idx) {
        if (*idx >= num_tokens) return;
        
        json_token_t *tok = &tokens[*idx];
        
        if (tok->type == JSON_OBJECT) {
            json_builder_object_begin(&builder);
            (*idx)++;
            
            int children = tok->size;
            for (int i = 0; i < children; i++) {
                // Key
                if (*idx < num_tokens && tokens[*idx].type == JSON_STRING) {
                    char key[256];
                    json_token_strcpy(input, &tokens[*idx], key, sizeof(key));
                    json_builder_key(&builder, key);
                    (*idx)++;
                    
                    // Value
                    rebuild_value(idx);
                }
            }
            
            json_builder_object_end(&builder);
        } else if (tok->type == JSON_ARRAY) {
            json_builder_array_begin(&builder);
            (*idx)++;
            
            int children = tok->size;
            for (int i = 0; i < children; i++) {
                rebuild_value(idx);
            }
            
            json_builder_array_end(&builder);
        } else if (tok->type == JSON_STRING) {
            char value[1024];
            json_token_strcpy(input, tok, value, sizeof(value));
            json_builder_string(&builder, value);
            (*idx)++;
        } else if (tok->type == JSON_PRIMITIVE) {
            if (json_token_is_true(input, tok)) {
                json_builder_bool(&builder, true);
            } else if (json_token_is_false(input, tok)) {
                json_builder_bool(&builder, false);
            } else if (json_token_is_null(input, tok)) {
                json_builder_null(&builder);
            } else {
                // Try as number
                int64_t int_val;
                double double_val;
                
                if (json_token_to_int64(input, tok, &int_val) == 0) {
                    json_builder_int(&builder, int_val);
                } else if (json_token_to_double(input, tok, &double_val) == 0) {
                    json_builder_double(&builder, double_val);
                }
            }
            (*idx)++;
        }
    }
    
    rebuild_value(&token_index);
    
    JSON_FREE(tokens);
    json_builder_free(&builder);
    
    return JSON_ERROR_NONE;
}

json_error_t json_minify(const char *input, char *output, size_t output_size) {
    if (input == NULL || output == NULL || output_size == 0) {
        return JSON_ERROR_INVAL;
    }
    
    size_t out_pos = 0;
    bool in_string = false;
    bool escape = false;
    
    for (const char *p = input; *p != '\0'; p++) {
        if (out_pos >= output_size - 1) {
            return JSON_ERROR_BUFFER_FULL;
        }
        
        if (escape) {
            output[out_pos++] = *p;
            escape = false;
            continue;
        }
        
        if (*p == '\\' && in_string) {
            output[out_pos++] = *p;
            escape = true;
            continue;
        }
        
        if (*p == '\"') {
            in_string = !in_string;
            output[out_pos++] = *p;
            continue;
        }
        
        if (in_string) {
            output[out_pos++] = *p;
            continue;
        }
        
        // Skip whitespace outside strings
        if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
            continue;
        }
        
        output[out_pos++] = *p;
    }
    
    output[out_pos] = '\0';
    return JSON_ERROR_NONE;
}

/* ============================================================================
 * PATH INSERT IMPLEMENTATION
 * ========================================================================== */

typedef struct {
    const char       *input;
    const json_token_t *tokens;
    int               num_tokens;
    json_builder_t   *builder;

    int               target_array_idx;   /* token index of array into which we insert */
    int               target_child_ord;   /* 0-based ordinal within that array */
    json_insert_mode_t mode;              /* BEFORE/AFTER */
    const char       *new_item_json;      /* raw JSON to insert */
    bool              injected;           /* ensure single insertion */
} json_insert_ctx_t;

/* ---- Path utilities ------------------------------------------------------ */

/* Split "a.b[2].c" into tokens ("a", "b[2]", "c") over a mutable copy. */
static char **json_path_split(char *path_copy, int *out_count) {
    if (!path_copy || !out_count) return NULL;
    int count = 1;
    for (char *p = path_copy; *p; ++p) if (*p == '.') count++;
    char **tokens = (char **)JSON_MALLOC((size_t)count * sizeof(char *));
    if (!tokens) return NULL;
    int idx = 0;
    char *start = path_copy;
    for (char *p = path_copy; ; ++p) {
        if (*p == '.' || *p == '\0') {
            tokens[idx++] = start;
            if (*p == '\0') break;
            *p = '\0';
            start = p + 1;
        }
    }
    *out_count = count;
    return tokens;
}

/* Parse token segment: "name[3]" => name="name", has_index=1, index=3
                        "name"   => name="name", has_index=0
                        "[0]"    => name=""     , has_index=1, index=0 (root array step) */
static int json_path_parse_token(char *token, char **out_name, int *out_has_index, int *out_index) {
    if (!token || !out_name || !out_has_index || !out_index) return -1;
    *out_has_index = 0;
    *out_index = -1;

    char *br = strchr(token, '[');
    if (!br) {
        *out_name = token;
        return 0;
    }

    *br = '\0';                 /* split name and [index] */
    *out_name = token;          /* may be empty for "[2]" (root array) */
    char *idx_start = br + 1;
    char *idx_end = strchr(idx_start, ']');
    if (!idx_end) return -1;

    char saved = *idx_end;
    *idx_end = '\0';
    if (*idx_start == '\0') { *idx_end = saved; return -1; }

    long val = 0;
    for (char *p = idx_start; *p; ++p) {
        if (!isdigit((unsigned char)*p)) { *idx_end = saved; return -1; }
        val = val * 10 + (*p - '0');
        if (val > INT_MAX) { *idx_end = saved; return -1; }
    }
    *idx_end = saved;

    *out_has_index = 1;
    *out_index = (int)val;

    /* Disallow multiple bracket groups in a single segment (use separate tokens) */
    if (strchr(idx_end + 1, '[') != NULL) return -1;

    return 0;
}

/* ---- Token utilities (over the parsed token stream) ---------------------- */

/* Advance to first token index after the entire subtree rooted at i. */
static int json_token_advance(const json_token_t *toks, int num, int i) {
    if (i < 0 || i >= num) return i + 1;
    int j = i + 1;
    int tend = toks[i].end;
    if (tend < 0) return i + 1;
    while (j < num && toks[j].start != -1 && toks[j].end != -1 && toks[j].start < tend) {
        j++;
    }
    return j;
}

/* Find value token index for key within object token obj_idx. Returns -1 if not found. */
static int json_find_object_value(const char *js, const json_token_t *toks, int num, int obj_idx, const char *key) {
    if (obj_idx < 0 || obj_idx >= num) return -1;
    if (toks[obj_idx].type != JSON_OBJECT) return -1;
    int i = obj_idx + 1;
    int pairs = toks[obj_idx].size;
    for (int p = 0; p < pairs; ++p) {
        if (i >= num) return -1;
        const json_token_t *keytok = &toks[i];
        if (keytok->type != JSON_STRING) return -1;
        int val_idx = i + 1;
        if (json_token_strcmp(js, keytok, key) == 0) {
            if (val_idx >= num) return -1;
            return val_idx;
        }
        /* Skip value subtree to the next key */
        i = json_token_advance(toks, num, val_idx);
    }
    return -1;
}

/* Find the token index of the n-th element inside array token arr_idx. */
static int json_find_array_nth(const json_token_t *toks, int num, int arr_idx, int n) {
    if (arr_idx < 0 || arr_idx >= num) return -1;
    if (toks[arr_idx].type != JSON_ARRAY) return -1;
    if (n < 0 || n >= toks[arr_idx].size) return -1;
    int i = arr_idx + 1;
    for (int k = 0; k < n; ++k) {
        i = json_token_advance(toks, num, i);
    }
    return i;
}

/* Resolve "user.array[3]" to (target_array_idx, target_child_ord). Returns 0 on success. */
static int json_resolve_insert_target(const char *js, const json_token_t *toks, int num,
                                      const char *path, int *out_arr_idx, int *out_ord) {
    if (!js || !toks || num <= 0 || !path || !out_arr_idx || !out_ord) return -1;

    /* Copy and split path */
    size_t path_len = strlen(path);
    char *path_copy = (char *)JSON_MALLOC(path_len + 1);
    if (!path_copy) return -1;
    memcpy(path_copy, path, path_len + 1);

    int seg_count = 0;
    char **segs = json_path_split(path_copy, &seg_count);
    if (!segs || seg_count <= 0) { JSON_FREE(segs); JSON_FREE(path_copy); return -1; }

    int cur = 0; /* root token */
    for (int s = 0; s < seg_count; ++s) {
        char *name = NULL;
        int has_index = 0, index = -1;
        if (json_path_parse_token(segs[s], &name, &has_index, &index) != 0) {
            JSON_FREE(segs); JSON_FREE(path_copy); return -1;
        }

        int is_last = (s == seg_count - 1);

        /* Descend by object key if present */
        if (name && name[0] != '\0') {
            int child = json_find_object_value(js, toks, num, cur, name);
            if (child < 0) { JSON_FREE(segs); JSON_FREE(path_copy); return -1; }
            cur = child;
        }

        if (has_index) {
            if (toks[cur].type != JSON_ARRAY) { JSON_FREE(segs); JSON_FREE(path_copy); return -1; }
            if (is_last) {
                *out_arr_idx = cur;
                *out_ord = index;
            } else {
                int elem = json_find_array_nth(toks, num, cur, index);
                if (elem < 0) { JSON_FREE(segs); JSON_FREE(path_copy); return -1; }
                cur = elem;
            }
        } else {
            if (is_last) { JSON_FREE(segs); JSON_FREE(path_copy); return -1; }
        }
    }

    JSON_FREE(segs);
    JSON_FREE(path_copy);
    return 0;
}

/* Forward decl */
static json_error_t json_rebuild_value(json_insert_ctx_t *ctx, int *pidx);

/* Emit a string value from token (used for array/object scalar values). */
static json_error_t json_emit_string_from_token(json_insert_ctx_t *ctx, const json_token_t *tok) {
    char tmp[1024];
    int n = json_token_strcpy(ctx->input, tok, tmp, sizeof(tmp));
    if (n < 0) return JSON_ERROR_INVAL;
    return json_builder_string(ctx->builder, tmp);
}

/* Emit an object key from token using the builder's key() API. */
static json_error_t json_emit_key_from_token(json_insert_ctx_t *ctx, const json_token_t *tok) {
    char keybuf[256];
    int n = json_token_strcpy(ctx->input, tok, keybuf, sizeof(keybuf));
    if (n < 0) return JSON_ERROR_INVAL;
    return json_builder_key(ctx->builder, keybuf);
}

/* Rebuild an object token: { "k": v, ... } */
static json_error_t json_rebuild_object(json_insert_ctx_t *ctx, int *pidx) {
    const json_token_t *toks = ctx->tokens;
    int num = ctx->num_tokens;

    int obj_idx = *pidx;
    json_error_t err = json_builder_object_begin(ctx->builder);
    if (err != JSON_ERROR_NONE) return err;
    (*pidx)++;

    /* The parser sets object->size to the number of key-value pairs */
    int pairs = toks[obj_idx].size;
    for (int i = 0; i < pairs; ++i) {
        /* Expect key */
        if (*pidx >= num || toks[*pidx].type != JSON_STRING) {
            return JSON_ERROR_INVAL;
        }
        err = json_emit_key_from_token(ctx, &toks[*pidx]);
        if (err != JSON_ERROR_NONE) return err;
        (*pidx)++;

        /* Emit value subtree */
        err = json_rebuild_value(ctx, pidx);
        if (err != JSON_ERROR_NONE) return err;
    }

    return json_builder_object_end(ctx->builder);
}

/* Rebuild an array token: [ ... ] (with optional injection if target matches) */
static json_error_t json_rebuild_array(json_insert_ctx_t *ctx, int *pidx) {
    const json_token_t *toks = ctx->tokens;

    int array_token_index = *pidx;
    json_error_t err = json_builder_array_begin(ctx->builder);
    if (err != JSON_ERROR_NONE) return err;
    (*pidx)++;

    int children = toks[array_token_index].size;
    for (int i = 0; i < children; ++i) {
        /* BEFORE insertion */
        if (!ctx->injected &&
            array_token_index == ctx->target_array_idx &&
            i == ctx->target_child_ord &&
            ctx->mode == JSON_INSERT_BEFORE) {
            err = json_builder_raw(ctx->builder, ctx->new_item_json);
            if (err != JSON_ERROR_NONE) return err;
            ctx->injected = true;
        }

        /* Emit element i */
        err = json_rebuild_value(ctx, pidx);
        if (err != JSON_ERROR_NONE) return err;

        /* AFTER insertion */
        if (!ctx->injected &&
            array_token_index == ctx->target_array_idx &&
            i == ctx->target_child_ord &&
            ctx->mode == JSON_INSERT_AFTER) {
            err = json_builder_raw(ctx->builder, ctx->new_item_json);
            if (err != JSON_ERROR_NONE) return err;
            ctx->injected = true;
        }
    }

    err = json_builder_array_end(ctx->builder);
    return err;
}

/* Generic value walker that delegates to object/array/scalars */
static json_error_t json_rebuild_value(json_insert_ctx_t *ctx, int *pidx) {
    if (*pidx >= ctx->num_tokens) return JSON_ERROR_INVAL;
    const json_token_t *tok = &ctx->tokens[*pidx];

    switch (tok->type) {
        case JSON_OBJECT:
            return json_rebuild_object(ctx, pidx);

        case JSON_ARRAY:
            return json_rebuild_array(ctx, pidx);

        case JSON_STRING: {
            json_error_t err = json_emit_string_from_token(ctx, tok);
            if (err != JSON_ERROR_NONE) return err;
            (*pidx)++;
            return JSON_ERROR_NONE;
        }

        case JSON_PRIMITIVE: {
            /* true/false/null or number */
            if (json_token_is_true(ctx->input, tok)) {
                json_error_t err = json_builder_bool(ctx->builder, true);
                if (err != JSON_ERROR_NONE) return err;
                (*pidx)++;
                return JSON_ERROR_NONE;
            } else if (json_token_is_false(ctx->input, tok)) {
                json_error_t err = json_builder_bool(ctx->builder, false);
                if (err != JSON_ERROR_NONE) return err;
                (*pidx)++;
                return JSON_ERROR_NONE;
            } else if (json_token_is_null(ctx->input, tok)) {
                json_error_t err = json_builder_null(ctx->builder);
                if (err != JSON_ERROR_NONE) return err;
                (*pidx)++;
                return JSON_ERROR_NONE;
            } else {
                /* number: prefer int64, else double, else raw */
                int64_t i64;
                double  dval;
                json_error_t err;
                if (json_token_to_int64(ctx->input, tok, &i64) == 0) {
                    err = json_builder_int(ctx->builder, i64);
                } else if (json_token_to_double(ctx->input, tok, &dval) == 0) {
                    err = json_builder_double(ctx->builder, dval);
                } else {
                    char buf[64];
                    int len = json_token_strcpy(ctx->input, tok, buf, sizeof(buf));
                    if (len < 0) return JSON_ERROR_INVAL;
                    err = json_builder_raw(ctx->builder, buf);
                }
                if (err != JSON_ERROR_NONE) return err;
                (*pidx)++;
                return JSON_ERROR_NONE;
            }
        }

        default:
            return JSON_ERROR_INVAL;
    }
}

/* ---- Public API ----------------------------------------------------------- */

static json_error_t json_insert_path_do(const char *input,
                                        const char *path,
                                        const char *new_item_json,
                                        json_insert_mode_t mode,
                                        char *output,
                                        size_t output_size) {
    if (!input || !path || !new_item_json || !output || output_size == 0) {
        return JSON_ERROR_INVAL;
    }

    /* First pass: count tokens */
    json_parser_t parser;
    json_parser_init(&parser);
    int token_count = json_parse(&parser, input, strlen(input), NULL, 0);
    if (token_count < 0) {
        return (json_error_t)token_count;
    }

    /* Second pass: actual tokens */
    json_token_t *tokens = (json_token_t *)JSON_MALLOC((size_t)token_count * sizeof(json_token_t));
    if (!tokens) return JSON_ERROR_NOMEM;
    json_parser_init(&parser);
    int num_tokens = json_parse(&parser, input, strlen(input), tokens, (unsigned int)token_count);
    if (num_tokens < 0) {
        JSON_FREE(tokens);
        return (json_error_t)num_tokens;
    }

    /* Resolve target */
    int target_array_idx = -1;
    int target_child_ord = -1;
    if (json_resolve_insert_target(input, tokens, num_tokens, path, &target_array_idx, &target_child_ord) != 0) {
        JSON_FREE(tokens);
        return JSON_ERROR_INVAL;
    }

    /* Build output (compact format by default) */
    json_builder_t builder;
    json_error_t err = json_builder_init(&builder, output, output_size);
    if (err != JSON_ERROR_NONE) { JSON_FREE(tokens); return err; }
    /* Leave pretty-print disabled (user can run json_pretty_print afterwards if desired) */

    json_insert_ctx_t ctx = {
        .input = input,
        .tokens = tokens,
        .num_tokens = num_tokens,
        .builder = &builder,
        .target_array_idx = target_array_idx,
        .target_child_ord = target_child_ord,
        .mode = mode,
        .new_item_json = new_item_json,
        .injected = false
    };

    int idx = 0;
    err = json_rebuild_value(&ctx, &idx);
    if (err == JSON_ERROR_NONE && !ctx.injected) {
        /* Should not happen if path was valid; treat as error to signal no-op */
        err = JSON_ERROR_INVAL;
    }

    json_builder_free(&builder);
    JSON_FREE(tokens);
    return err;
}

json_error_t json_insert_path(const char *input,
                              const char *path,
                              const char *new_item_json,
                              char *output,
                              size_t output_size) {
    return json_insert_path_do(input, path, new_item_json, JSON_INSERT_AFTER, output, output_size);
}

json_error_t json_insert_path_ex(const char *input,
                                 const char *path,
                                 const char *new_item_json,
                                 json_insert_mode_t mode,
                                 char *output,
                                 size_t output_size) {
    return json_insert_path_do(input, path, new_item_json, mode, output, output_size);
}

typedef struct {
    const char *input;
    const json_token_t *tokens;
    int num_tokens;
    json_builder_t *builder;
    
    /* Path tracking */
    char **path_segments;
    int *path_indices;
    int *path_has_index;
    int path_count;
    int current_segment;
    
    const json_value_t *new_value;
    bool value_set;
} json_set_ctx_t;

/* Forward declarations */
static json_error_t json_set_rebuild_value(json_set_ctx_t *ctx, int *pidx, int depth);
static json_error_t json_set_rebuild_object(json_set_ctx_t *ctx, int *pidx, int depth);
static json_error_t json_set_rebuild_array(json_set_ctx_t *ctx, int *pidx, int depth);

/* Check if we're at the target path at given depth */
static bool json_set_at_target(json_set_ctx_t *ctx, int depth) {
    return depth == ctx->path_count;
}

/* Check if current segment matches at given depth */
static bool json_set_matches_segment(json_set_ctx_t *ctx, int depth, const char *key) {
    if (depth >= ctx->path_count) return false;
    return strcmp(ctx->path_segments[depth], key) == 0;
}

/* Emit the replacement value using the builder */
static json_error_t json_set_emit_value(json_set_ctx_t *ctx) {
    const json_value_t *val = ctx->new_value;
    json_error_t err;
    
    switch (val->type) {
        case JSON_VALUE_RAW:
            err = json_builder_raw(ctx->builder, val->data.str_val);
            break;
        case JSON_VALUE_STRING:
            err = json_builder_string(ctx->builder, val->data.str_val);
            break;
        case JSON_VALUE_INT:
            err = json_builder_int(ctx->builder, val->data.int_val);
            break;
        case JSON_VALUE_DOUBLE:
            err = json_builder_double(ctx->builder, val->data.double_val);
            break;
        case JSON_VALUE_BOOL:
            err = json_builder_bool(ctx->builder, val->data.bool_val);
            break;
        case JSON_VALUE_NULL:
            err = json_builder_null(ctx->builder);
            break;
        default:
            return JSON_ERROR_INVAL;
    }
    
    if (err == JSON_ERROR_NONE) {
        ctx->value_set = true;
    }
    return err;
}

/* Create a new value at the target path (when path doesn't exist) */
static json_error_t json_set_create_path(json_set_ctx_t *ctx, int depth) {
    json_error_t err;
    
    /* If we're at the target, emit the value */
    if (json_set_at_target(ctx, depth)) {
        return json_set_emit_value(ctx);
    }
    
    /* Need to create intermediate structure */
    int has_index = ctx->path_has_index[depth];
    
    if (has_index) {
        /* Create array */
        err = json_builder_array_begin(ctx->builder);
        if (err != JSON_ERROR_NONE) return err;
        
        /* Fill array up to target index with nulls */
        int target_idx = ctx->path_indices[depth];
        for (int i = 0; i < target_idx; i++) {
            err = json_builder_null(ctx->builder);
            if (err != JSON_ERROR_NONE) return err;
        }
        
        /* Recurse for the element at target index */
        err = json_set_create_path(ctx, depth + 1);
        if (err != JSON_ERROR_NONE) return err;
        
        return json_builder_array_end(ctx->builder);
    } else {
        /* Create object */
        err = json_builder_object_begin(ctx->builder);
        if (err != JSON_ERROR_NONE) return err;
        
        /* Add the key */
        err = json_builder_key(ctx->builder, ctx->path_segments[depth]);
        if (err != JSON_ERROR_NONE) return err;
        
        /* Recurse for the value */
        err = json_set_create_path(ctx, depth + 1);
        if (err != JSON_ERROR_NONE) return err;
        
        return json_builder_object_end(ctx->builder);
    }
}

/* Rebuild object with potential replacement */
static json_error_t json_set_rebuild_object(json_set_ctx_t *ctx, int *pidx, int depth) {
    const json_token_t *toks = ctx->tokens;
    int num = ctx->num_tokens;
    int obj_idx = *pidx;
    
    json_error_t err = json_builder_object_begin(ctx->builder);
    if (err != JSON_ERROR_NONE) return err;
    (*pidx)++;
    
    int pairs = toks[obj_idx].size;
    bool found_target = false;
    
    /* Copy existing pairs, replacing target if found */
    for (int i = 0; i < pairs; i++) {
        if (*pidx >= num || toks[*pidx].type != JSON_STRING) {
            return JSON_ERROR_INVAL;
        }
        
        /* Get key */
        char keybuf[256];
        int n = json_token_strcpy(ctx->input, &toks[*pidx], keybuf, sizeof(keybuf));
        if (n < 0) return JSON_ERROR_INVAL;
        
        bool is_target = json_set_matches_segment(ctx, depth, keybuf);
        
        err = json_builder_key(ctx->builder, keybuf);
        if (err != JSON_ERROR_NONE) return err;
        (*pidx)++;
        
        if (is_target && json_set_at_target(ctx, depth + 1)) {
            /* Replace this value */
            err = json_set_emit_value(ctx);
            if (err != JSON_ERROR_NONE) return err;
            /* Skip original value */
            *pidx = json_token_advance(toks, num, *pidx);
            found_target = true;
        } else if (is_target) {
            /* Continue down the path */
            err = json_set_rebuild_value(ctx, pidx, depth + 1);
            if (err != JSON_ERROR_NONE) return err;
            found_target = true;
        } else {
            /* Copy original value */
            err = json_set_rebuild_value(ctx, pidx, depth + 1);
            if (err != JSON_ERROR_NONE) return err;
        }
    }
    
    /* If target key doesn't exist, add it */
    if (!found_target && depth < ctx->path_count && !ctx->path_has_index[depth]) {
        if (json_set_matches_segment(ctx, depth, ctx->path_segments[depth]) || 
            strcmp(ctx->path_segments[depth], "") != 0) {
            
            err = json_builder_key(ctx->builder, ctx->path_segments[depth]);
            if (err != JSON_ERROR_NONE) return err;
            
            err = json_set_create_path(ctx, depth + 1);
            if (err != JSON_ERROR_NONE) return err;
        }
    }
    
    return json_builder_object_end(ctx->builder);
}

/* Rebuild array with potential replacement */
static json_error_t json_set_rebuild_array(json_set_ctx_t *ctx, int *pidx, int depth) {
    const json_token_t *toks = ctx->tokens;
    int array_idx = *pidx;
    
    json_error_t err = json_builder_array_begin(ctx->builder);
    if (err != JSON_ERROR_NONE) return err;
    (*pidx)++;
    
    int children = toks[array_idx].size;
    int target_idx = (depth < ctx->path_count && ctx->path_has_index[depth]) 
                     ? ctx->path_indices[depth] : -1;
    
    /* Copy/replace existing elements */
    for (int i = 0; i < children; i++) {
        if (i == target_idx && json_set_at_target(ctx, depth + 1)) {
            /* Replace this element */
            err = json_set_emit_value(ctx);
            if (err != JSON_ERROR_NONE) return err;
            /* Skip original */
            *pidx = json_token_advance(toks, ctx->num_tokens, *pidx);
        } else if (i == target_idx) {
            /* Continue down path */
            err = json_set_rebuild_value(ctx, pidx, depth + 1);
            if (err != JSON_ERROR_NONE) return err;
        } else {
            /* Copy original */
            err = json_set_rebuild_value(ctx, pidx, depth + 1);
            if (err != JSON_ERROR_NONE) return err;
        }
    }
    
    /* Extend array if needed */
    if (target_idx >= children) {
        /* Fill with nulls up to target */
        for (int i = children; i < target_idx; i++) {
            err = json_builder_null(ctx->builder);
            if (err != JSON_ERROR_NONE) return err;
        }
        /* Add new value */
        err = json_set_create_path(ctx, depth + 1);
        if (err != JSON_ERROR_NONE) return err;
    }
    
    return json_builder_array_end(ctx->builder);
}

/* Rebuild any value type */
static json_error_t json_set_rebuild_value(json_set_ctx_t *ctx, int *pidx, int depth) {
    if (*pidx >= ctx->num_tokens) return JSON_ERROR_INVAL;
    const json_token_t *tok = &ctx->tokens[*pidx];
    
    switch (tok->type) {
        case JSON_OBJECT:
            return json_set_rebuild_object(ctx, pidx, depth);
            
        case JSON_ARRAY:
            return json_set_rebuild_array(ctx, pidx, depth);
            
        case JSON_STRING: {
            char tmp[1024];
            int n = json_token_strcpy(ctx->input, tok, tmp, sizeof(tmp));
            if (n < 0) return JSON_ERROR_INVAL;
            json_error_t err = json_builder_string(ctx->builder, tmp);
            if (err != JSON_ERROR_NONE) return err;
            (*pidx)++;
            return JSON_ERROR_NONE;
        }
        
        case JSON_PRIMITIVE: {
            json_error_t err;
            if (json_token_is_true(ctx->input, tok)) {
                err = json_builder_bool(ctx->builder, true);
            } else if (json_token_is_false(ctx->input, tok)) {
                err = json_builder_bool(ctx->builder, false);
            } else if (json_token_is_null(ctx->input, tok)) {
                err = json_builder_null(ctx->builder);
            } else {
                int64_t i64;
                double dval;
                if (json_token_to_int64(ctx->input, tok, &i64) == 0) {
                    err = json_builder_int(ctx->builder, i64);
                } else if (json_token_to_double(ctx->input, tok, &dval) == 0) {
                    err = json_builder_double(ctx->builder, dval);
                } else {
                    char buf[64];
                    int len = json_token_strcpy(ctx->input, tok, buf, sizeof(buf));
                    if (len < 0) return JSON_ERROR_INVAL;
                    err = json_builder_raw(ctx->builder, buf);
                }
            }
            if (err != JSON_ERROR_NONE) return err;
            (*pidx)++;
            return JSON_ERROR_NONE;
        }
        
        default:
            return JSON_ERROR_INVAL;
    }
}

/* Set path's value */
json_error_t json_set_path_value(const char *input,
                                 const char *path,
                                 const json_value_t *value,
                                 char *output,
                                 size_t output_size) {
    if (!path || !value || !output || output_size == 0) {
        return JSON_ERROR_INVAL;
    }
    
    /* Handle empty input - create from scratch */
    bool empty_input = (input == NULL || input[0] == '\0');
    
    /* Parse path */
    size_t path_len = strlen(path);
    char *path_copy = (char *)JSON_MALLOC(path_len + 1);
    if (!path_copy) return JSON_ERROR_NOMEM;
    memcpy(path_copy, path, path_len + 1);
    
    int seg_count = 0;
    char **segs = json_path_split(path_copy, &seg_count);
    if (!segs || seg_count <= 0) {
        JSON_FREE(segs);
        JSON_FREE(path_copy);
        return JSON_ERROR_INVAL;
    }
    
    /* Parse each segment */
    char **names = (char **)JSON_MALLOC(seg_count * sizeof(char *));
    int *indices = (int *)JSON_MALLOC(seg_count * sizeof(int));
    int *has_index = (int *)JSON_MALLOC(seg_count * sizeof(int));
    
    if (!names || !indices || !has_index) {
        JSON_FREE(names);
        JSON_FREE(indices);
        JSON_FREE(has_index);
        JSON_FREE(segs);
        JSON_FREE(path_copy);
        return JSON_ERROR_NOMEM;
    }
    
    for (int i = 0; i < seg_count; i++) {
        if (json_path_parse_token(segs[i], &names[i], &has_index[i], &indices[i]) != 0) {
            JSON_FREE(names);
            JSON_FREE(indices);
            JSON_FREE(has_index);
            JSON_FREE(segs);
            JSON_FREE(path_copy);
            return JSON_ERROR_INVAL;
        }
    }
    
    /* Initialize builder */
    json_builder_t builder;
    json_error_t err = json_builder_init(&builder, output, output_size);
    if (err != JSON_ERROR_NONE) {
        JSON_FREE(names);
        JSON_FREE(indices);
        JSON_FREE(has_index);
        JSON_FREE(segs);
        JSON_FREE(path_copy);
        return err;
    }
    
    if (empty_input) {
        /* Create structure from scratch */
        json_set_ctx_t ctx = {
            .input = NULL,
            .tokens = NULL,
            .num_tokens = 0,
            .builder = &builder,
            .path_segments = names,
            .path_indices = indices,
            .path_has_index = has_index,
            .path_count = seg_count,
            .current_segment = 0,
            .new_value = value,
            .value_set = false
        };
        
        err = json_set_create_path(&ctx, 0);
    } else {
        /* Parse existing JSON */
        json_parser_t parser;
        json_parser_init(&parser);
        int token_count = json_parse(&parser, input, strlen(input), NULL, 0);
        if (token_count < 0) {
            json_builder_free(&builder);
            JSON_FREE(names);
            JSON_FREE(indices);
            JSON_FREE(has_index);
            JSON_FREE(segs);
            JSON_FREE(path_copy);
            return (json_error_t)token_count;
        }
        
        json_token_t *tokens = (json_token_t *)JSON_MALLOC((size_t)token_count * sizeof(json_token_t));
        if (!tokens) {
            json_builder_free(&builder);
            JSON_FREE(names);
            JSON_FREE(indices);
            JSON_FREE(has_index);
            JSON_FREE(segs);
            JSON_FREE(path_copy);
            return JSON_ERROR_NOMEM;
        }
        
        json_parser_init(&parser);
        int num_tokens = json_parse(&parser, input, strlen(input), tokens, (unsigned int)token_count);
        if (num_tokens < 0) {
            JSON_FREE(tokens);
            json_builder_free(&builder);
            JSON_FREE(names);
            JSON_FREE(indices);
            JSON_FREE(has_index);
            JSON_FREE(segs);
            JSON_FREE(path_copy);
            return (json_error_t)num_tokens;
        }
        
        /* Build modified JSON */
        json_set_ctx_t ctx = {
            .input = input,
            .tokens = tokens,
            .num_tokens = num_tokens,
            .builder = &builder,
            .path_segments = names,
            .path_indices = indices,
            .path_has_index = has_index,
            .path_count = seg_count,
            .current_segment = 0,
            .new_value = value,
            .value_set = false
        };
        
        int idx = 0;
        err = json_set_rebuild_value(&ctx, &idx, 0);
        
        JSON_FREE(tokens);
    }
    
    json_builder_free(&builder);
    JSON_FREE(names);
    JSON_FREE(indices);
    JSON_FREE(has_index);
    JSON_FREE(segs);
    JSON_FREE(path_copy);
    
    return err;
}

#endif /* JSON_IMPLEMENTATION */
