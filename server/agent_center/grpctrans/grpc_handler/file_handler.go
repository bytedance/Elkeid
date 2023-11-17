package grpc_handler

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	pb "github.com/bytedance/Elkeid/server/agent_center/grpctrans/proto"
	"github.com/bytedance/Elkeid/server/agent_center/httptrans/client"
	"io"
	"os"
	"path"
	"path/filepath"
)

type FileExtHandler struct {
	FileBaseDir string
}

type TosResult struct {
	Code  int
	Data  string
	Error string
}

func (h *FileExtHandler) Init() {
	if !common.IsFileExist(h.FileBaseDir) {
		err := os.MkdirAll(h.FileBaseDir, os.ModePerm)
		if err != nil {
			ylog.Errorf("FileExtHandler_Init", "FileExtHandler create dir %s, error %s", h.FileBaseDir, err.Error())
			os.Exit(-1)
		}
	}
}

func (h *FileExtHandler) Download(request *pb.DownloadRequest, server pb.FileExt_DownloadServer) error {
	file, err := client.GetFileFromRemote(request.GetToken())
	if err != nil {
		ylog.Errorf("Download", "GetFileFromRemote token %s error %s", request.GetToken(), err.Error())
		return err
	}
	out, err := unZipSingleFileFromMemory(file)
	if err != nil {
		ylog.Errorf("Download", "unZipSingleFileFromMemory token %s error %s", request.GetToken(), err.Error())
		return err
	}

	//根据2M(2097152) 拆分发送
	bufRead := bytes.NewBuffer(out)
	buf := make([]byte, 2097152)
	for {
		buf = bufRead.Next(2097150)
		if len(buf) == 0 {
			break
		}

		resp := &pb.DownloadResponse{
			Data: buf,
		}
		err = server.Send(resp)
		if err != nil {
			ylog.Errorf("Download", "error while sending chunk: %s", err.Error())
			return err
		}
	}
	return nil
}

func (h *FileExtHandler) Upload(stream pb.FileExt_UploadServer) (err error) {
	var fp *os.File
	var fileRequest *pb.UploadRequest
	var filePath, token string
	var fileBuf *bufio.Writer

	firstChunk := true
	for {
		fileRequest, err = stream.Recv()
		if err != nil {
			//finished
			if err == io.EOF {
				ylog.Infof("FileExtHandler_Upload", "write file finished: %s", filePath)
				break
			}

			ylog.Errorf("FileExtHandler_Upload", "failed while reading chunks from stream: %s", err.Error())
			goto Fail
		}

		if firstChunk {
			filePath = path.Join(h.FileBaseDir, fileRequest.Token)
			fp, err = os.Create(filePath)
			if err != nil {
				ylog.Errorf("FileExtHandler_Upload", "Unable to create file: %s", filePath)
				stream.SendAndClose(&pb.UploadResponse{Status: pb.UploadResponse_FAILED})
				goto Fail
			}
			fileBuf = bufio.NewWriter(fp)
			token = fileRequest.Token
			firstChunk = false
		}
		_, err = fileBuf.Write(fileRequest.Data)
		if err != nil {
			ylog.Errorf("FileExtHandler_Upload", "Unable to write chunk of file: %s , error: %s", filePath, err.Error())
			stream.SendAndClose(&pb.UploadResponse{Status: pb.UploadResponse_FAILED})
			goto Fail
		}
	}

	if fileBuf != nil {
		err = fileBuf.Flush()
		if err != nil {
			ylog.Errorf("FileExtHandler_Upload", "Unable to write chunk of file: %s , error: %s", filePath, err.Error())
			goto Fail
		}
	}

	fp.Close()

	handlerFile(token, filePath)
	err = stream.SendAndClose(&pb.UploadResponse{Status: pb.UploadResponse_SUCCESS})
	if err != nil {
		ylog.Errorf("FileExtHandler_Upload", "fail to send response to client %s , filePath: %s", err.Error(), filePath)
		return err
	}

	ylog.Infof("FileExtHandler_Upload", "Successfully received and stored the file: %s", filePath)
	return nil

Fail:
	if fp != nil {
		fp.Close()
		os.Remove(filePath)
	}
	ylog.Infof("FileExtHandler_Upload", "Upload failed: %s , filePath: %s", err.Error(), filePath)
	return err
}

const (
	TaskStatusFail    = "failed"
	TaskStatusSuccess = "succeed"
)

func handlerFile(token, filePath string) {
	item := map[string]string{
		"token":     token,
		"status":    TaskStatusSuccess,
		"data_type": "5100",
		"msg":       "",
	}
	zipPath := filePath + ".zip"
	defer func() {
		ylog.Infof("handlerFile", "PushTask2Manager %#v", item)
		err := GlobalGRPCPool.PushTask2Manager(item)
		if err != nil {
			ylog.Errorf("handlerFile", "PushTask2Manager error %s", err.Error())
		}

		//删除文件单处理完后
		err = os.Remove(filePath)
		if err != nil {
			ylog.Errorf("handlerFile", "Remove file %s, error %s", filePath, err.Error())
		} else {
			ylog.Infof("handlerFile", "Remove file %s ok!", filePath)
		}

		//删除文件单处理完后
		err = os.Remove(zipPath)
		if err != nil {
			ylog.Errorf("handlerFile", "Remove file %s, error %s", zipPath, err.Error())
		} else {
			ylog.Infof("handlerFile", "Remove file %s ok!", zipPath)
		}
	}()

	err := zipFile(zipPath, filePath)
	if err != nil {
		item["status"] = TaskStatusFail
		item["msg"] = fmt.Sprintf("handlerFile, zipFile error %s, path %s.", err.Error(), filePath)
		ylog.Errorf("handlerFile", "zipFile error %s, path %s.", err.Error(), filePath)
		return
	}

	hash, err := fileMD5(zipPath)
	if err != nil {
		item["status"] = TaskStatusFail
		item["msg"] = fmt.Sprintf("handlerFile, fileMD5 error %s, path %s.", err.Error(), filePath)
		ylog.Errorf("handlerFile", "fileMD5 error %s, path %s.", err.Error(), filePath)
		return
	}

	newPath, err := client.UploadFile(zipPath, hash, token)
	if err != nil {
		item["status"] = TaskStatusFail
		item["msg"] = fmt.Sprintf("handlerFile, UploadFile error %s, path %s.", err.Error(), filePath)
		ylog.Errorf("handlerFile", "UploadFile error %s, path %s.", err.Error(), filePath)
		return
	}

	item["status"] = TaskStatusSuccess
	item["msg"] = newPath
}

// zip file
func zipFile(zipFilePath, srcFilePath string) error {
	newZipFile, err := os.Create(zipFilePath)
	if err != nil {
		return err
	}
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer zipWriter.Close()

	srcFile, err := os.Open(srcFilePath)
	if err != nil {
		return err
	}
	info, err := srcFile.Stat()
	if err != nil {
		return err
	}
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = filepath.Base(srcFile.Name())
	header.Method = zip.Deflate
	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(writer, srcFile)
	if err != nil {
		return err
	}
	return nil
}

func unZipSingleFileFromMemory(in []byte) ([]byte, error) {
	zipReader, err := zip.NewReader(bytes.NewReader(in), int64(len(in)))
	if err != nil {
		return nil, err
	}
	for _, zipFile := range zipReader.File {
		unzippedFileBytes, err := readZipFile(zipFile)
		if err != nil {
			return nil, err
		}
		return unzippedFileBytes, nil
	}
	return nil, errors.New("no zip file found")
}

func readZipFile(zf *zip.File) ([]byte, error) {
	f, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func fileMD5(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	md5Handler := md5.New()
	if _, err := io.Copy(md5Handler, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(md5Handler.Sum(nil)), nil
}
