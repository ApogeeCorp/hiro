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

	"github.com/ModelRocket/hiro/pkg/hiro/pb"
	"github.com/ModelRocket/hiro/pkg/ptr"
	"github.com/ModelRocket/hiro/pkg/safe"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AudienceGet handles the audience get rpc request
func (s *RPCServer) AudienceGet(ctx context.Context, req *pb.AudienceGetRequest) (*pb.Audience, error) {
	var params AudienceGetInput

	switch req.Query.(type) {
	case *pb.AudienceGetRequest_Id:
		params.AudienceID = ptr.ID(req.GetId())

	case *pb.AudienceGetRequest_Name:
		params.Name = ptr.String(req.GetName())
	}

	aud, err := s.ctrl.AudienceGet(ctx, params)
	if err != nil {
		return nil, err
	}

	rval := &pb.Audience{
		Id:          aud.ID.String(),
		Name:        aud.Name,
		Description: safe.String(aud.Description),
		CreatedAt:   timestamppb.New(aud.CreatedAt),
		UpdatedAt:   timestamppb.New(safe.Time(*aud.UpdatedAt, aud.CreatedAt)),
		Permissions: aud.Permissions,
	}

	if len(aud.Metadata) > 0 {
		if v, err := structpb.NewValue(map[string]interface{}(aud.Metadata)); err == nil {
			rval.Metadata = v.GetStructValue()
		}
	}

	return rval, nil
}
