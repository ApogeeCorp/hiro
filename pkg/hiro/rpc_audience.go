/*
 * This file is part of the Model Rocket Hiro Stack
 * Copyright (c) 2020 Model Rocket LLC.
 *
 * https://githuh.com/ModelRocket/hiro
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package hiro

import (
	"context"
	"time"

	"github.com/ModelRocket/hiro/pkg/hiro/pb"
	"github.com/ModelRocket/hiro/pkg/oauth"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/ModelRocket/hiro/pkg/safe"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	pbSecretMap = map[pb.Secret_SecretType]SecretType{
		pb.Secret_Token:   SecretTypeToken,
		pb.Secret_Session: SecretTypeSession,
	}

	pbAlgoMap = map[pb.Secret_TokenAlgorithm]oauth.TokenAlgorithm{
		pb.Secret_None:  oauth.TokenAlgorithmNone,
		pb.Secret_RS256: oauth.TokenAlgorithmRS256,
		pb.Secret_HS256: oauth.TokenAlgorithmHS256,
	}

	apiSecretMap = map[SecretType]pb.Secret_SecretType{
		SecretTypeToken:   pb.Secret_Token,
		SecretTypeSession: pb.Secret_Session,
	}

	apiAlgoMap = map[oauth.TokenAlgorithm]pb.Secret_TokenAlgorithm{
		oauth.TokenAlgorithmNone:  pb.Secret_None,
		oauth.TokenAlgorithmRS256: pb.Secret_RS256,
		oauth.TokenAlgorithmHS256: pb.Secret_HS256,
	}
)

// ToProto converts the audiece to its protobuf conterpart
func (a Instance) ToProto() (*pb.Instance, error) {
	secrets := make([]*pb.Secret, 0)

	for _, s := range a.Secrets {
		secrets = append(secrets, s.ToProto())
	}

	createdAt, err := ptypes.TimestampProto(a.CreatedAt)
	if err != nil {
		return nil, err
	}

	updatedAt, err := ptypes.TimestampProto(safe.Time(a.UpdatedAt))
	if err != nil {
		return nil, err
	}

	meta, err := structpb.NewStruct(a.Metadata)
	if err != nil {
		return nil, err
	}

	return &pb.Instance{
		Id:              a.ID.String(),
		Name:            a.Name,
		Slug:            a.Slug,
		Description:     a.Description,
		Secrets:         secrets,
		TokenAlgorithm:  apiAlgoMap[a.TokenAlgorithm],
		TokenLifetime:   uint64(a.TokenLifetime.Seconds()),
		SessionLifetime: uint64(a.TokenLifetime.Seconds()),
		Permissions:     a.Permissions,
		Metadata:        meta,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}, err
}

// FromProto convert the proto instance to an api instance
func (a *Instance) FromProto(p *pb.Instance) {
	a.Secrets = make([]*Secret, 0)

	for _, s := range p.Secrets {
		var sec Secret

		sec.FromProto(s)

		a.Secrets = append(a.Secrets, &sec)
	}

	if p.CreatedAt != nil {
		a.CreatedAt = p.CreatedAt.AsTime()
	}

	if p.UpdatedAt != nil {
		a.UpdatedAt = ptr.Time(p.UpdatedAt.AsTime())
	}

	a.ID = ID(p.Id)
	a.Name = p.Name
	a.Slug = p.Slug
	a.Description = p.Description
	a.TokenAlgorithm = pbAlgoMap[p.TokenAlgorithm]
	a.TokenLifetime = time.Duration(p.TokenLifetime) * time.Second
	a.SessionLifetime = time.Duration(p.SessionLifetime) * time.Second
	a.Permissions = p.Permissions
	a.Metadata = p.Metadata.AsMap()
}

// InstanceCreate implements the pb.HiroServer interface
func (s *RPCServer) InstanceCreate(ctx context.Context, params *pb.InstanceCreateRequest) (*pb.Instance, error) {
	inst, err := s.Controller.InstanceCreate(ctx, InstanceCreateInput{
		Name:            params.Name,
		Description:     params.Description,
		TokenAlgorithm:  pbAlgoMap[params.TokenAlgorithm],
		TokenLifetime:   time.Duration(params.TokenLifetime) * time.Second,
		SessionLifetime: time.Duration(params.SessionLifetime) * time.Second,
		Permissions:     params.Permissions,
		Metadata:        params.Metadata.AsMap(),
	})
	if err != nil {
		return nil, err
	}

	return inst.ToProto()
}

// InstanceUpdate implements the pb.HiroServer interface
func (s *RPCServer) InstanceUpdate(ctx context.Context, params *pb.InstanceUpdateRequest) (*pb.Instance, error) {
	var algo *oauth.TokenAlgorithm
	var tl, sl *time.Duration
	var perms *InstancePermissionsUpdate

	if params.TokenAlgorithm != nil {
		a := pbAlgoMap[*params.TokenAlgorithm]
		algo = &a
	}

	if params.TokenLifetime != nil {
		tl = ptr.Duration(time.Duration(*params.TokenLifetime) * time.Second)
	}

	if params.SessionLifetime != nil {
		sl = ptr.Duration(time.Duration(*params.SessionLifetime) * time.Second)
	}

	if params.Permissions != nil {
		perms = &InstancePermissionsUpdate{
			Add:       params.Permissions.Add,
			Remove:    params.Permissions.Remove,
			Overwrite: params.Permissions.Overwrite,
		}
	}

	inst, err := s.Controller.InstanceUpdate(ctx, InstanceUpdateInput{
		Name:            params.Name,
		Description:     params.Description,
		TokenAlgorithm:  algo,
		TokenLifetime:   tl,
		SessionLifetime: sl,
		Permissions:     perms,
		Metadata:        params.Metadata.AsMap(),
	})
	if err != nil {
		return nil, err
	}

	return inst.ToProto()
}

// InstanceGet implements the pb.HiroServer interface
func (s *RPCServer) InstanceGet(ctx context.Context, params *pb.InstanceGetRequest) (*pb.Instance, error) {
	a, err := s.Controller.InstanceGet(ctx, InstanceGetInput{
		InstanceID: ID(params.GetId()),
		Name:       ptr.NilString(params.GetName()),
	})
	if err != nil {
		return nil, err
	}

	return a.ToProto()
}

// InstanceList implements the pb.HiroServer interface
func (s *RPCServer) InstanceList(req *pb.InstanceListRequest, stream pb.Hiro_InstanceListServer) error {
	auds, err := s.Controller.InstanceList(stream.Context(), InstanceListInput{
		Limit:  &req.Limit,
		Offset: &req.Offset,
	})
	if err != nil {
		return err
	}

	for _, a := range auds {
		p, err := a.ToProto()
		if err != nil {
			return err
		}
		stream.Send(p)
	}

	return nil
}

// InstanceDelete implements the pb.HiroServer interface
func (s *RPCServer) InstanceDelete(ctx context.Context, params *pb.InstanceDeleteRequest) (*empty.Empty, error) {
	err := s.Controller.InstanceDelete(ctx, InstanceDeleteInput{
		InstanceID: ID(params.Id),
	})

	return nil, err
}
