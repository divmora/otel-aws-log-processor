# Multi-stage build for Go Lambda
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the Lambda function
# Use TARGETARCH to support multi-arch builds (amd64/arm64)
ARG TARGETARCH
ARG VERSION
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags="-w -s -X github.com/divmora/otel-aws-log-processor/pkg/version.Version=${VERSION} -X github.com/divmora/otel-aws-log-processor/pkg/sender.Version=${VERSION}" -o bootstrap ./cmd/lambda

# Final stage - use AWS Lambda base image
FROM public.ecr.aws/lambda/provided:al2023

# Copy the binary to Lambda task root and set execution permissions
COPY --from=builder /build/bootstrap ${LAMBDA_TASK_ROOT}/bootstrap
RUN chmod 755 ${LAMBDA_TASK_ROOT}/bootstrap

# Set the CMD to your handler
CMD [ "bootstrap" ]
