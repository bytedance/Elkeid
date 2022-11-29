package container

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/Elkeid/plugins/collector/process"
	"github.com/docker/docker/api/types"
	docker "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
	crierr "k8s.io/cri-api/pkg/errors"
)

func IsNotFound(err error) bool {
	if crierr.IsNotFound(err) {
		return true
	}
	if docker.IsErrNotFound(err) {
		return true
	}
	return false
}

type Client interface {
	ListContainers(ctx context.Context) ([]Container, error)
	Exec(ctx context.Context, containerID string, name string, arg ...string) ([]byte, error)
	Close()
	Runtime() string
}
type Container struct {
	ID         string
	Name       string
	ImageID    string
	ImageName  string
	State      string
	Pid        string
	Pns        string
	Runtime    string
	CreateTime string
}
type criClient struct {
	c  cri.RuntimeServiceClient
	cc *grpc.ClientConn
}

func (c *criClient) ListContainers(ctx context.Context) ([]Container, error) {
	containers := []Container{}
	resp, err := c.c.ListContainers(ctx, &cri.ListContainersRequest{})
	if err != nil {
		return nil, err
	}
	for _, criContainer := range resp.Containers {
		container := Container{
			ID:         criContainer.GetId(),
			Name:       criContainer.GetMetadata().GetName(),
			ImageID:    strings.TrimLeft(criContainer.GetImageRef(), "sha256:"),
			ImageName:  strings.TrimLeft(criContainer.GetImage().GetImage(), "sha256:"),
			State:      StateName[int32(criContainer.GetState())],
			CreateTime: strconv.FormatInt(criContainer.CreatedAt/1000000000, 10),
			Runtime:    c.Runtime(),
		}
		if container.State == StateName[int32(RUNNING)] {
			if resp, err := c.c.ContainerStatus(ctx, &cri.ContainerStatusRequest{ContainerId: criContainer.Id, Verbose: true}); err == nil {
				if info, ok := resp.Info["info"]; ok {
					p := struct {
						Pid int `json:"pid"`
					}{}
					if err := json.Unmarshal([]byte(info), &p); err == nil {
						container.Pid = strconv.Itoa(p.Pid)
						if p.Pid > 0 {
							if p, err := process.NewProcess(container.Pid); err == nil {
								container.Pns, _ = p.Namespace("pid")
							}
						}
					}
				}
				// real image name
				if resp.Status.GetImage().GetImage() != "" {
					container.ImageName = strings.TrimLeft(resp.Status.GetImage().GetImage(), "sha256:")
				}
			}
		}
		containers = append(containers, container)
	}
	return containers, nil
}
func (c *criClient) Exec(ctx context.Context, containerID string, name string, arg ...string) ([]byte, error) {
	var timeout int64
	if ddl, ok := ctx.Deadline(); ok {
		d := time.Until(ddl).Seconds()
		if d > 0 {
			timeout = int64(d)
		}
	}
	cmd := make([]string, len(arg)+1)
	cmd[0] = name
	copy(cmd[1:], arg)
	resp, err := c.c.ExecSync(ctx, &cri.ExecSyncRequest{
		ContainerId: containerID,
		Timeout:     timeout,
		Cmd:         cmd,
	})
	if err != nil {
		return nil, err
	}
	if resp.ExitCode != 0 {
		return nil, errors.New(string(resp.Stderr))
	}
	return bytes.Join([][]byte{resp.Stdout, resp.Stderr}, []byte{'\n'}), nil
}
func (c *criClient) Close() {
	c.cc.Close()
}
func (c *criClient) Runtime() string {
	return "cri"
}

type dockerClient struct {
	c *docker.Client
}

func (c *dockerClient) ListContainers(ctx context.Context) ([]Container, error) {
	containers := []Container{}
	resp, err := c.c.ContainerList(ctx, types.ContainerListOptions{All: true})
	if err != nil {
		return nil, err
	}
	for _, dockerContainer := range resp {
		container := Container{
			ID:         dockerContainer.ID,
			ImageID:    strings.TrimLeft(dockerContainer.ImageID, "sha256:"),
			ImageName:  strings.TrimLeft(dockerContainer.Image, "sha256:"),
			State:      dockerContainer.State,
			CreateTime: strconv.FormatInt(dockerContainer.Created, 10),
			Runtime:    c.Runtime(),
		}
		if resp, err := c.c.ContainerInspect(ctx, dockerContainer.ID); err == nil {
			container.Name = strings.TrimPrefix(resp.Name, "/")
			if container.State == StateName[int32(RUNNING)] {
				container.Pid = strconv.Itoa(resp.State.Pid)
				if resp.State.Pid > 0 {
					if p, err := process.NewProcess(container.Pid); err == nil {
						container.Pns, _ = p.Namespace("pid")
					}
				}
			}
		}
		if container.Name == "" && len(dockerContainer.Names) > 0 {
			container.Name = dockerContainer.Names[0]
		}
		containers = append(containers, container)
	}
	return containers, nil
}
func (c *dockerClient) Exec(ctx context.Context, containerID string, name string, arg ...string) ([]byte, error) {
	cmd := make([]string, len(arg)+1)
	cmd[0] = name
	copy(cmd[1:], arg)
	createResp, err := c.c.ContainerExecCreate(ctx, containerID, types.ExecConfig{Cmd: cmd, AttachStdout: true, AttachStderr: true})
	if err != nil {
		return nil, err
	}
	attachResp, err := c.c.ContainerExecAttach(ctx, createResp.ID, types.ExecStartCheck{})
	if err != nil {
		return nil, err
	}
	defer attachResp.Close()
	go func() {
		<-ctx.Done()
		attachResp.Close()
		// ! The process maybe still alive!
	}()
	stdout := bytes.NewBuffer(nil)
	stderr := bytes.NewBuffer(nil)
	_, err = stdcopy.StdCopy(stdout, stderr, attachResp.Reader)
	if err != nil {
		return nil, err
	}
	inspectResp, err := c.c.ContainerExecInspect(ctx, createResp.ID)
	if err == nil && inspectResp.ExitCode != 0 {
		if len(stderr.Bytes()) != 0 {
			return nil, errors.New(stderr.String())
		}
		if len(stdout.Bytes()) != 0 {
			return nil, errors.New(stdout.String())
		}
		return nil, errors.New("unknown error")
	}
	return bytes.Join([][]byte{stdout.Bytes(), stderr.Bytes()}, []byte{'\n'}), nil
}
func (c *dockerClient) Close()          { c.c.Close() }
func (c *dockerClient) Runtime() string { return "docker" }
func NewClients() []Client {
	var clients []Client
	var err error
	var cc *grpc.ClientConn
	for _, path := range []string{
		"unix:///run/containerd/containerd.sock",
		"unix:///run/crio/crio.sock",
		"unix:///var/run/cri-dockerd.sock",
	} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		cc, err = grpc.DialContext(ctx, path,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.FailOnNonTempDialError(true),
			grpc.WithBlock(),
			grpc.WithReturnConnectionError(),
		)
		if err == nil {
			c := cri.NewRuntimeServiceClient(cc)
			_, err := c.Version(context.Background(), &cri.VersionRequest{})
			if err == nil {
				clients = append(clients, &criClient{c: c, cc: cc})
			} else {
				cc.Close()
			}
		}
		cancel()
	}
	var client *docker.Client
	client, err = docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
	if err == nil {
		clients = append(clients, &dockerClient{c: client})
	}
	return clients
}
