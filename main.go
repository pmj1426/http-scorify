package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/scorify/schema"
)

type Schema struct {
	URL            string `key:"url"`
	Verb           string `key:"verb" default:"GET" enum:"GET,POST,PUT,DELETE,PATCH,HEAD,OPTIONS,CONNECT,TRACE"`
	ExpectedOutput string `key:"expected_output"`
	MatchType      string `key:"match_type" default:"statusCode" enum:"statusCode,substringMatch,exactMatch,regexMatch"`
	Insecure       bool   `key:"insecure"`
	Headers        string `key:"headers"`
	Body           string `key:"body"`
	ContentType    string `key:"content_type" default:"empty" enum:"plain/text,application/json,x-www-form-urlencoded,empty"`
}

func Validate(config string) error {
	conf := Schema{}

	err := schema.Unmarshal([]byte(config), &conf)
	if err != nil {
		return err
	}

	if conf.URL == "" {
		return fmt.Errorf("url must be provided; got: %v", conf.URL)
	}

	if !slices.Contains([]string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"}, conf.Verb) {
		return fmt.Errorf("invalid command provided: %v", conf.Verb)
	}

	if !slices.Contains([]string{"statusCode", "substringMatch", "exactMatch", "regexMatch"}, conf.MatchType) {
		return fmt.Errorf("invalid match type provided: %v", conf.MatchType)
	}

	if conf.ExpectedOutput == "" {
		return fmt.Errorf("expected_output must be provided; got: %v", conf.ExpectedOutput)
	}

	if conf.MatchType == "statusCode" {
		status_code, err := strconv.Atoi(conf.ExpectedOutput)
		if err != nil {
			return fmt.Errorf("invalid status code provided: %v; %q", conf.ExpectedOutput, err)
		}

		if status_code < 100 || status_code > 599 {
			return fmt.Errorf("invalid status code provided: %d", status_code)
		}
	}

	if conf.Headers != "" {
		for _, raw := range strings.Split(conf.Headers, ";") {
			if raw == "" {
				return fmt.Errorf("header format must be \"header:value;header:value\" ; got: %v", conf.Headers)
			}
			parts := strings.SplitN(raw, ":", 2)
			if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
				return fmt.Errorf("header format must be \"header:value;header:value\" ; got: %v", conf.Headers)
			}
		}
	}

	if conf.ContentType == "empty" && conf.Body != "" {
		return fmt.Errorf("body must not be provided when using empty Content-Type; got: %v", conf.Body)
	}

	if conf.ContentType != "empty" && conf.Body == "" {
		return fmt.Errorf("body must be provided when using non-empty Content-Type; got: %v", conf.Body)
	}

	if !slices.Contains([]string{"plain/text", "application/json", "x-www-form-urlencoded", "empty"}, conf.ContentType) {
		return fmt.Errorf("invalid content type provided: %v", conf.ContentType)
	}

	return nil
}

func Run(ctx context.Context, config string) error {
	conf := Schema{}

	err := schema.Unmarshal([]byte(config), &conf)
	if err != nil {
		return err
	}

	var requestType string

	switch conf.Verb {
	case "GET":
		requestType = http.MethodGet
	case "POST":
		requestType = http.MethodPost
	case "PUT":
		requestType = http.MethodPut
	case "DELETE":
		requestType = http.MethodDelete
	case "PATCH":
		requestType = http.MethodPatch
	case "HEAD":
		requestType = http.MethodHead
	case "OPTIONS":
		requestType = http.MethodOptions
	case "CONNECT":
		requestType = http.MethodConnect
	case "TRACE":
		requestType = http.MethodTrace
	default:
		return fmt.Errorf("provided invalid command/http verb: %q", conf.Verb)
	}
	var req *http.Request
	if conf.ContentType == "empty" {
		req, err = http.NewRequestWithContext(ctx, requestType, conf.URL, nil)
		if err != nil {
			return fmt.Errorf("encounted error while creating request: %v", err.Error())
		}

	} else {
		req, err = http.NewRequestWithContext(ctx, requestType, conf.URL, bytes.NewBufferString(conf.Body))
		if err != nil {
			return fmt.Errorf("encounted error while creating request: %v", err.Error())
		}
		req.Header.Add("Content-Type", conf.ContentType)
	}

	if conf.Headers != "" {
		if strings.Contains(conf.Headers, ";") {
			headers := strings.Split(conf.Headers, ";")
			for _, element := range headers {
				keyvalue := strings.Split(element, ":")
				if len(keyvalue) != 2 {
					return fmt.Errorf("header format must be \"header:value;header:value\" ; got: %v", conf.Headers)
				}
				req.Header.Add(keyvalue[0], keyvalue[1])
			}
		} else {
			keyvalue := strings.Split(conf.Headers, ":")
			if len(keyvalue) != 2 {
				return fmt.Errorf("header format must be \"header:value;header:value\" ; got: %v", conf.Headers)
			}
			req.Header.Add(keyvalue[0], keyvalue[1])
		}
	}

	tls_config := &tls.Config{InsecureSkipVerify: conf.Insecure}
	http_transpot := &http.Transport{TLSClientConfig: tls_config}
	client := &http.Client{Transport: http_transpot}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("encounted error while making request: %v", err.Error())
	}
	defer resp.Body.Close()

	switch conf.MatchType {
	case "statusCode":
		status_code, err := strconv.Atoi(conf.ExpectedOutput)
		if err != nil {
			return fmt.Errorf("invalid status code provided: %v; %q", conf.ExpectedOutput, err)
		}

		if resp.StatusCode != status_code {
			return fmt.Errorf("expected status code: %d; got: %d", status_code, resp.StatusCode)
		}
	case "substringMatch":
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("encountered error while reading response body: %v", err)
		}

		if !strings.Contains(string(body), conf.ExpectedOutput) {
			return fmt.Errorf("expected output not found in response body")
		}
	case "exactMatch":
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("encountered error while reading response body: %v", err)
		}

		if string(body) != conf.ExpectedOutput {
			return fmt.Errorf("expected output not found in response body")
		}
	case "regexMatch":
		pattern, err := regexp.Compile(conf.ExpectedOutput)
		if err != nil {
			return fmt.Errorf("invalid regex pattern provided: %v; %q", conf.ExpectedOutput, err)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("encountered error while reading response body: %v", err)
		}

		if !pattern.Match(body) {
			return fmt.Errorf("expected output not found in response body")
		}
	default:
		return fmt.Errorf("invalid match type provided: %v", conf.MatchType)
	}

	return nil
}
