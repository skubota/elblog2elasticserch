package main

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/olivere/elastic"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

var Version string

const (
	esIndex = "elblog"
	esType  = "elb"
)

type ElbAccessLog struct {
	Protocol               string `json:"protocol"`
	Timestamp              string `json:"timestamp"`
	Elb                    string `json:"elb"`
	ClientIpAddress        string `json:"client_ip_address"`
	BackendIpAddress       string `json:"backend_ip_address"`
	RequestProcessingTime  int64  `json:"request_processing_time"`
	BackendProcessingTime  int64  `json:"backend_processing_time"`
	ResponseProcessingTime int64  `json:"response_processing_time"`
	ElbStatusCode          int64  `json:"elb_status_code"`
	BackendStatusCode      int64  `json:"backend_status_code"`
	ReceivedBytes          int64  `json:"received_bytes"`
	SentBytes              int64  `json:"sent_bytes"`
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

		// Create an index.
		indexName := fmt.Sprintf("%s-%s", esIndex, time.Now().Format("2006-01-02"))
		//indexName := esIndex

		// Read the body of the S3 object.
		bytes, err := ioutil.ReadAll(log_data)
		if err != nil {
			log.Printf("ioutil.ReadAll err != nil")
			log.Fatal(err)
		}

		lines := 0
		for _, line := range strings.Split(string(bytes), "\n") {
			if len(line) != 0 {
				putDocumentIntoES(indexName, line)
				lines++
			}
		}
		log.Printf("read line: %d\n", lines)
	}
	return nil
}

// Index a recode of the S3 object, which is a single HTTP access log record.
func putDocumentIntoES(indexName string, line string) error {

	r := csv.NewReader(strings.NewReader(line))
	r.Comma = ' ' // space
	fields, err := r.Read()

	doc, err := arrayToElbAccessLog(fields)
	if err != nil {
		log.Printf("arrayToElbAccessLog err != nil")
		log.Fatal(err)
		return nil
	}

	ctxb := context.Background()

	bulk := connectToElastic().
		Bulk().
		Index(indexName).
		Type(esType)

	bulk.Add(elastic.NewBulkIndexRequest().Doc(doc))

	if _, err := bulk.Do(ctxb); err != nil {
		log.Println(err)
	}

	return nil
}

func arrayToElbAccessLog(line []string) (*ElbAccessLog, error) {

	// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
	var rb, sb, rqt, st, bst, bt, rst int64
	rqt, _ = strconv.ParseInt(line[5], 10, 32)
	bt, _ = strconv.ParseInt(line[6], 10, 32)
	rst, _ = strconv.ParseInt(line[7], 10, 32)
	st, _ = strconv.ParseInt(line[8], 10, 32)
	bst, _ = strconv.ParseInt(line[9], 10, 32)
	rb, _ = strconv.ParseInt(line[10], 10, 32)
	sb, _ = strconv.ParseInt(line[11], 10, 32)

	elb := &ElbAccessLog{
		Protocol:               line[0],
		Timestamp:              line[1],
		Elb:                    line[2],
		ClientIpAddress:        line[3],
		BackendIpAddress:       line[4],
		RequestProcessingTime:  rqt,
		BackendProcessingTime:  bt,
		ResponseProcessingTime: rst,
		ElbStatusCode:          st,
		BackendStatusCode:      bst,
		ReceivedBytes:          rb,
		SentBytes:              sb,
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

func connectToElastic() *elastic.Client {
	endpoint := fmt.Sprintf(os.Getenv("ES_ENDPOINT"))
	elasticClient, err := elastic.NewClient(
		elastic.SetURL(endpoint),
		elastic.SetSniff(false),
	)
	if err != nil {
		log.Println(err)
		time.Sleep(3 * time.Second)

	} else {
		return elasticClient
	}
	return nil
}

func main() {
	lambda.Start(HandleRequest)
}
