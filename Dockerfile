# Multi-stage build for Go Lambda
FROM golang:1.26-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Ensure release.sig exists in builder so COPY never errors
RUN if [ ! -f /build/release.sig ]; then touch /build/release.sig; fi

# Build the Lambda function
# Use TARGETARCH to support multi-arch builds (amd64/arm64)
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG RELEASE_SIG=none

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-w -s \
    -X github.com/divmora/otel-aws-log-processor/pkg/version.Version=${VERSION} \
    -X github.com/divmora/otel-aws-log-processor/pkg/version.GitCommit=${COMMIT} \
    -X github.com/divmora/otel-aws-log-processor/pkg/version.BuildDate=${DATE} \
    -X github.com/divmora/otel-aws-log-processor/pkg/version.ReleaseSignature=${RELEASE_SIG} \
    -X github.com/divmora/otel-aws-log-processor/pkg/sender.Version=${VERSION}" \
    -o bootstrap ./cmd/lambda

# Final stage - use AWS Lambda base image
FROM public.ecr.aws/lambda/provided:al2023

# Copy the binary and optional release signature to Lambda task root
COPY --from=builder /build/bootstrap ${LAMBDA_TASK_ROOT}/bootstrap
COPY --from=builder /build/release.sig ${LAMBDA_TASK_ROOT}/release.sig
RUN chmod 755 ${LAMBDA_TASK_ROOT}/bootstrap && \
    if [ ! -s ${LAMBDA_TASK_ROOT}/release.sig ]; then rm -f ${LAMBDA_TASK_ROOT}/release.sig; fi

# Set the CMD to your handler
CMD [ "bootstrap" ]
