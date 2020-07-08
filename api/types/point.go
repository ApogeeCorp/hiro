// Code generated by go-swagger; DO NOT EDIT.

package types

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"bytes"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Point A geoJSON Point
//
// swagger:model Point
type Point struct {

	// coordinates
	Coordinates Point2D `json:"coordinates,omitempty"`
}

// Type gets the type of this subtype
func (m *Point) Type() string {
	return "Point"
}

// SetType sets the type of this subtype
func (m *Point) SetType(val string) {
}

// UnmarshalJSON unmarshals this object with a polymorphic type from a JSON structure
func (m *Point) UnmarshalJSON(raw []byte) error {
	var data struct {

		// coordinates
		Coordinates Point2D `json:"coordinates,omitempty"`
	}
	buf := bytes.NewBuffer(raw)
	dec := json.NewDecoder(buf)
	dec.UseNumber()

	if err := dec.Decode(&data); err != nil {
		return err
	}

	var base struct {
		/* Just the base type fields. Used for unmashalling polymorphic types.*/

		Type string `json:"type"`
	}
	buf = bytes.NewBuffer(raw)
	dec = json.NewDecoder(buf)
	dec.UseNumber()

	if err := dec.Decode(&base); err != nil {
		return err
	}

	var result Point

	if base.Type != result.Type() {
		/* Not the type we're looking for. */
		return errors.New(422, "invalid type value: %q", base.Type)
	}

	result.Coordinates = data.Coordinates

	*m = result

	return nil
}

// MarshalJSON marshals this object with a polymorphic type to a JSON structure
func (m Point) MarshalJSON() ([]byte, error) {
	var b1, b2, b3 []byte
	var err error
	b1, err = json.Marshal(struct {

		// coordinates
		Coordinates Point2D `json:"coordinates,omitempty"`
	}{

		Coordinates: m.Coordinates,
	})
	if err != nil {
		return nil, err
	}
	b2, err = json.Marshal(struct {
		Type string `json:"type"`
	}{

		Type: m.Type(),
	})
	if err != nil {
		return nil, err
	}

	return swag.ConcatJSON(b1, b2, b3), nil
}

// Validate validates this point
func (m *Point) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCoordinates(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Point) validateCoordinates(formats strfmt.Registry) error {

	if swag.IsZero(m.Coordinates) { // not required
		return nil
	}

	if err := m.Coordinates.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("coordinates")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Point) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Point) UnmarshalBinary(b []byte) error {
	var res Point
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}