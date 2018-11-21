package main

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/edoardo849/apex-aws-signer"
	"gopkg.in/olivere/elastic.v3"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

var Version string

const (
	esIndex               = "elblogidx"
	esType                = "elb"
)

type ElbAccessLog struct {
	Protocol               string `json:"protocol"`
	Timestamp              string `json:"timestamp"`
	Elb                    string `json:"elb"`
	ClientIpAddress        string `json:"client_ip_address"`
	BackendIpAddress       string `json:"backend_ip_address"`
	RequestProcessingTime  string `json:"request_processing_time"`
	BackendProcessingTime  string `json:"backend_processing_time"`
	ResponseProcessingTime string `json:"response_processing_time"`
	ElbStatusCode          string `json:"elb_status_code"`
	BackendStatusCode      string `json:"backend_status_code"`
	ReceivedBytes          string `json:"received_bytes"`
	SentBytes              string `json:"sent_bytes"`
	Request                string `json:"request"`
	UserAgent              string `json:"user_agent"`
	SslCipher              string `json:"ssl_cipher"`
	SslProcotol            string `json:"ssl_protocol"`
	TargetGrpArn           string `json:"target_group_arn"`
	TraceID                string `json:"trace_id"`
	DomainName             string `json:"domain_name"`
	CertArn                string `json:"chosen_cert_arn"`
	RulePriority           string `json:"matched_rule_priority"`
	RequestCreationTime    string `json:"request_creation_time"`
	ActionsExecuted        string `json:"actions_executed"`
	RedirectUrl            string `json:"redirect_url"`
}

func extract(zr io.Reader) (io.Reader, error) {
	return gzip.NewReader(zr)
}

func HandleRequest(ctx context.Context, event events.S3Event) error {
	// Iterate all the S3 events, while extracting S3 bucket and filename.
	for _, rec := range event.Records {
		// S3 session
		svc := s3.New(session.New(&aws.Config{Region: aws.String(rec.AWSRegion)}))
		log.Printf("[%s - %s] Bucket = %s, Key = %s \n", rec.EventSource, rec.EventTime, rec.S3.Bucket.Name, rec.S3.Object.Key)
		// get the S3 object, i.e. file content
		s3out, err := svc.GetObject(&s3.GetObjectInput{
			Bucket: aws.String(rec.S3.Bucket.Name),
			Key:    aws.String(rec.S3.Object.Key),
		})
		if err != nil {
			log.Printf("svc.GetObject err != nil")
			log.Fatal(err)
		}
		// extract
		log_data, err := extract(s3out.Body)
		if err != nil {
			log.Printf("extract err != nil %s %s", os.Stderr, err)
			log.Fatal(err)
		}

		// working with Elasticsearch
		transport := signer.NewTransport(session.New(&aws.Config{Region: aws.String(rec.AWSRegion)}), elasticsearchservice.ServiceName)

		httpClient := &http.Client{
			Transport: transport,
		}

		// Use the client with Olivere's elastic client
		client, err := elastic.NewClient(
			elastic.SetSniff(false),
			elastic.SetURL(os.Getenv("ES_ENDPOINT")),
			elastic.SetScheme("https"),
			elastic.SetHttpClient(httpClient),
		)
		if err != nil {
			log.Printf("elastic.NewClient err != nil")
			panic(err)
		}

		// Create an index.
		indexName := esIndex

		// Read the body of the S3 object.
		bytes, err := ioutil.ReadAll(log_data)
		if err != nil {
			log.Printf("ioutil.ReadAll err != nil")
			log.Fatal(err)
		}

		lines := 0
		for _, line := range strings.Split(string(bytes), "\n") {
			if len(line) != 0 {
				putDocumentIntoES(client, indexName, line)
				lines++
			}
		}
		log.Printf("read line: %d\n", lines)
	}
	return nil
}

// Index a recode of the S3 object, which is a single HTTP access log record.
func putDocumentIntoES(c *elastic.Client, indexName string, line string) error {
	//log.Printf("line: %s\n", line)

	r := csv.NewReader(strings.NewReader(line))
	r.Comma = ' ' // space
	fields, err := r.Read()

	doc, err := arrayToElbAccessLog(fields)
	if err != nil {
		log.Printf("arrayToElbAccessLog err != nil")
		log.Fatal(err)
		return nil
	}

	put1, err := c.Index().
		Index(indexName).
		Type(esType).
		BodyJson(doc).
		Do()
	if err != nil {
		log.Printf("c.Index err != nil %s",put1)
		panic(err)
	}
	//log.Printf("Indexed elb access log %s to index %s, type %s\n", put1.Id, put1.Index, put1.Type)

	return nil
}

func arrayToElbAccessLog(line []string) (*ElbAccessLog, error) {

	elb := &ElbAccessLog{
		Protocol:               line[0],
		Timestamp:              line[1],
		Elb:                    line[2],
		ClientIpAddress:        line[3],
		BackendIpAddress:       line[4],
		RequestProcessingTime:  line[5],
		BackendProcessingTime:  line[6],
		ResponseProcessingTime: line[7],
		ElbStatusCode:          line[8],
		BackendStatusCode:      line[9],
		ReceivedBytes:          line[10],
		SentBytes:              line[11],
		Request:                line[12],
		UserAgent:              line[13],
		SslCipher:              line[14],
		SslProcotol:            line[15],
		TargetGrpArn:           line[16],
		TraceID:                line[17],
		DomainName:             line[18],
		CertArn:                line[19],
		RulePriority:           line[20],
		RequestCreationTime:    line[21],
		ActionsExecuted:        line[22],
		RedirectUrl:            line[23],
	}
	return elb, nil
}

func main() {
	lambda.Start(HandleRequest)
}
