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

// define
var Version string

const (
	esIndex = "elblog"
	esType  = "elb"
)

// log structure
type ElbAccessLog struct {
	Protocol               string  `json:"protocol"`
	Timestamp              string  `json:"timestamp"`
	Elb                    string  `json:"elb"`
	ClientIpAddress        string  `json:"client_ip_address"`
	ClientSourcePort       int64   `json:"client_source_port"`
	BackendIpAddress       string  `json:"backend_ip_address"`
	BackendDstPort         int64   `json:"backend_destination_port"`
	RequestProcessingTime  float64 `json:"request_processing_time"`
	BackendProcessingTime  float64 `json:"backend_processing_time"`
	ResponseProcessingTime float64 `json:"response_processing_time"`
	ElbStatusCode          int64   `json:"elb_status_code"`
	BackendStatusCode      int64   `json:"backend_status_code"`
	ReceivedBytes          int64   `json:"received_bytes"`
	SentBytes              int64   `json:"sent_bytes"`
	Request                string  `json:"request"`
	UserAgent              string  `json:"user_agent"`
	SslCipher              string  `json:"ssl_cipher"`
	SslProcotol            string  `json:"ssl_protocol"`
	TargetGrpArn           string  `json:"target_group_arn"`
	TraceId                string  `json:"trace_id"`
	DomainName             string  `json:"domain_name"`
	CertArn                string  `json:"chosen_cert_arn"`
	RulePriority           string  `json:"matched_rule_priority"`
	RequestCreationTime    string  `json:"request_creation_time"`
	ActionsExecuted        string  `json:"actions_executed"`
	RedirectUrl            string  `json:"redirect_url"`
}

// generic function

// gzip extractor
func extract(zr io.Reader) (io.Reader, error) {
	return gzip.NewReader(zr)
}

// slice popper
func slice_pop(slice []string) (string, []string) {
	last := slice[len(slice)-1]
	slice = slice[:len(slice)-1]
	return last, slice
}

// lamda handle function
func HandleRequest(ctx context.Context, event events.S3Event) error {
	// Iterate all the S3 events, while extracting S3 bucket and filename.
	for _, rec := range event.Records {
		// S3 session
		svc := s3.New(session.New(&aws.Config{Region: aws.String(rec.AWSRegion)}))

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

		// Read the body of the S3 object.
		bytes, err := ioutil.ReadAll(log_data)
		if err != nil {
			log.Printf("ioutil.ReadAll err != nil")
			log.Fatal(err)
		}

		ctxb := context.Background()
		bulk := connectToElastic().
			Bulk().
			Index(indexName).
			Type(esType)

		if bulk == nil {
			log.Printf("connectToElastic err == nil")
			log.Fatal(err)
		}

		lines := 0
		for _, line := range strings.Split(string(bytes), "\n") {
			if len(line) != 0 {
				r := csv.NewReader(strings.NewReader(line))
				r.Comma = ' ' // space
				fields, err := r.Read()

				doc, err := arrayToElbAccessLog(fields)
				if err != nil {
					log.Printf("arrayToElbAccessLog err != nil")
					log.Fatal(err)
					return nil
				}
				bulk.Add(elastic.NewBulkIndexRequest().Doc(doc))
				lines++
			}
		}
		if _, err := bulk.Do(ctxb); err != nil {
			log.Println(err)
		}

		log.Printf("read line: %d\n", lines)
	}
	return nil
}

// elb log line array to struct
func arrayToElbAccessLog(line []string) (*ElbAccessLog, error) {

	// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
	var client_ip, backend_ip string
	var client_port, backend_port int64
	var status_code, backend_status_code, recv_bytes, send_bytes int64
	var req_time, backend_time, responce_time float64

	client_ip, client_port = split_aplusp(line[3])
	backend_ip, backend_port = split_aplusp(line[4])

	status_code, _ = strconv.ParseInt(line[8], 10, 32)
	backend_status_code, _ = strconv.ParseInt(line[9], 10, 32)
	recv_bytes, _ = strconv.ParseInt(line[10], 10, 32)
	send_bytes, _ = strconv.ParseInt(line[11], 10, 32)

	req_time, _ = strconv.ParseFloat(line[5], 64)
	backend_time, _ = strconv.ParseFloat(line[6], 64)
	responce_time, _ = strconv.ParseFloat(line[7], 64)

	elb := &ElbAccessLog{
		Protocol:               line[0],
		Timestamp:              line[1],
		Elb:                    line[2],
		ClientIpAddress:        client_ip,
		ClientSourcePort:       client_port,
		BackendIpAddress:       backend_ip,
		BackendDstPort:         backend_port,
		RequestProcessingTime:  req_time,
		BackendProcessingTime:  backend_time,
		ResponseProcessingTime: responce_time,
		ElbStatusCode:          status_code,
		BackendStatusCode:      backend_status_code,
		ReceivedBytes:          recv_bytes,
		SentBytes:              send_bytes,
		Request:                line[12],
		UserAgent:              line[13],
		SslCipher:              line[14],
		SslProcotol:            line[15],
		TargetGrpArn:           line[16],
		TraceId:                line[17],
		DomainName:             line[18],
		CertArn:                line[19],
		RulePriority:           line[20],
		RequestCreationTime:    line[21],
		ActionsExecuted:        line[22],
		RedirectUrl:            line[23],
	}
	return elb, nil
}

// connect ESS
func connectToElastic() *elastic.Client {
	endpoint := fmt.Sprintf(os.Getenv("ES_ENDPOINT"))
	for i := 0; i < 3; i++ {
		elasticClient, err := elastic.NewClient(
			elastic.SetURL(endpoint),
			elastic.SetSniff(false),
		)
		if err != nil {
			log.Printf("elastic.NewClient err != nil %s", err)
			//time.Sleep(3 * time.Second)
		} else {
			return elasticClient
		}
	}
	return nil
}

// address + poer splitter
func split_aplusp(aplusp string) (string, int64) {
	var ip string
	var port int64
	c := strings.Count(aplusp, ":")
	addr := strings.Split(aplusp, ":")

	if c == 0 {
		return aplusp, 0
	} else if c == 1 {
		// ipv4
		ip = addr[0]
		port, _ = strconv.ParseInt(addr[1], 10, 32)
	} else {
		// ipv6
		var port_str string
		port_str, addr = slice_pop(addr)
		ip = strings.Join(addr, ":")
		port, _ = strconv.ParseInt(port_str, 10, 32)
	}
	return ip, port
}

// main
func main() {
	lambda.Start(HandleRequest)
}

// EoF
