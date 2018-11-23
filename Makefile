
##[ EDIT] #####################
NAME := main
FUNC := elblog2elasticserch
##############################

GOCMD=/usr/bin/go
GOFMT=/usr/bin/gofmt
AWS=/usr/bin/aws
ZIP=/usr/bin/zip
RM=/bin/rm
JQ=/usr/bin/jq

GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

VERSION := 0.1
MINVER  :=$(shell date -u +.%Y%m%d)

all: clean fmt build
install: pub

.PHONY: deps
deps:
	$(GOGET) github.com/aws/aws-sdk-go
	$(GOGET) gopkg.in/olivere/elastic.v3
	$(GOGET) github.com/edoardo849/apex-aws-signer

.PHONY: build
build:
	GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags "-X main.Version=$(VERSION)$(MINVER)" -o $(NAME)

.PHONY: clean
clean:
	$(GOCLEAN)
	$(RM) -rf $(NAME)
	$(RM) -rf $(NAME).zip

.PHONY: pub
pub:
	$(ZIP) $(NAME).zip $(NAME)
	$(AWS) lambda update-function-code --function-name $(FUNC) --zip-file fileb://$(NAME).zip | $(JQ)

.PHONY: fmt
fmt:
	gofmt -w $(NAME).go
