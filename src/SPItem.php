<?php
/**
 * This file is part of the SPOIL library.
 *
 * @author     Quetzy Garcia <quetzyg@impensavel.com>
 * @copyright  2014-2016
 *
 * For the full copyright and license information,
 * please view the LICENSE.md file that was distributed
 * with this source code.
 */

namespace Impensavel\Spoil;

use Impensavel\Spoil\Exception\SPBadMethodCallException;
use Impensavel\Spoil\Exception\SPRuntimeException;

class SPItem extends SPObject implements SPItemInterface
{
    use SPPropertiesTrait;
    use SPTimestampsTrait;

    /**
     * SharePoint List
     *
     * @var  SPList
     */
    protected $list;

    /**
     * SharePoint ID
     *
     * @var  int
     */
    protected $id = 0;

    /**
     * SharePoint Item constructor
     *
     * @param   SPList $list    SharePoint List object
     * @param   array  $payload OData response payload
     * @param   array  $extra   Extra payload values to map
     * @throws  SPBadMethodCallException
     */
    public function __construct(SPList $list, array $payload, array $extra = [])
    {
        $this->mapper = array_merge([
            'spType'   => 'odata.type',
            'id'       => 'Id',
            'guid'     => 'GUID',
            'title'    => 'Title',
            'created'  => 'Created',
            'modified' => 'Modified',
        ], $extra);

        $this->list = $list;

        $this->hydrate($payload);
    }

    /**
     * Get SharePoint List
     *
     * @return  SPList
     */
    public function getSPList()
    {
        return $this->list;
    }

    /**
     * Get SharePoint ID
     *
     * @return  int
     */
    public function getID()
    {
        return $this->id;
    }

    /**
     * {@inheritdoc}
     */
    public function toArray()
    {
        return [
            'sp_type'  => $this->spType,
            'id'       => $this->id,
            'guid'     => $this->guid,
            'title'    => $this->title,
            'created'  => $this->created,
            'modified' => $this->modified,
            'extra'    => $this->extra,
        ];
    }

    /**
     * Get all SharePoint Items
     *
     * @param   SPList $list     SharePoint List
     * @param   array  $settings Instantiation settings
     * @throws  SPRuntimeException
     * @return  array
     */
    public static function getAll(SPList $list, array $settings = [])
    {
        $settings = array_replace_recursive([
            'top'   => 5000, // SharePoint Item threshold
        ], $settings, [
            'extra' => [],   // Extra SharePoint Item properties to map
        ]);

        $json = $list->request("_api/web/Lists(guid'".$list->getGUID()."')/items", [
            'headers' => [
                'Authorization' => 'Bearer '.$list->getSPAccessToken(),
                'Accept'        => 'application/json',
            ],

            'query'   => [
                'top' => $settings['top'],
            ],
        ]);

        $items = [];

        foreach ($json['value'] as $item) {
            $items[$item['GUID']] = new static($list, $item, $settings['extra']);
        }

        return $items;
    }

    /**
     * Get a SharePoint Item by ID
     *
     * @param   SPList $list  SharePoint List
     * @param   int    $id    Item ID
     * @param   array  $extra Extra payload values to map
     * @throws  SPRuntimeException
     * @return  SPItem
     */
    public static function getByID(SPList $list, $id, array $extra = [])
    {
        $json = $list->request("_api/web/Lists(guid'".$list->getGUID()."')/items(".$id.")", [
            'headers' => [
                'Authorization' => 'Bearer '.$list->getSPAccessToken(),
                'Accept'        => 'application/json',
            ],
        ]);

        return new static($list, $json, $extra);
    }

    /**
     * Create a SharePoint Item
     *
     * @param   SPList $list       SharePoint List
     * @param   array  $properties SharePoint Item properties (Title, ...)
     * @param   array  $extra      Extra payload values to map
     * @throws  SPRuntimeException
     * @return  SPItem
     */
    public static function create(SPList $list, array $properties, array $extra = [])
    {
        $properties = array_replace_recursive($properties, [
            'odata.type' => $list->getItemType(),
        ]);

        $body = json_encode($properties);

        $json = $list->request("_api/web/Lists(guid'".$list->getGUID()."')/items", [
            'headers' => [
                'Authorization'   => 'Bearer '.$list->getSPAccessToken(),
                'Accept'          => 'application/json',
                'X-RequestDigest' => $list->getSPContextInfo()->getFormDigest(),
                'Content-type'    => 'application/json',
                'Content-length'  => strlen($body),
            ],

            'body'    => $body,

        ], 'POST');

        return new static($list, $json, $extra);
    }

    /**
     * Update a SharePoint Item
     *
     * @param   array $properties SharePoint Item properties (Title, ...)
     * @throws  SPRuntimeException
     * @return  SPItem
     */
    public function update(array $properties)
    {
        $properties = array_replace_recursive($properties, [
            'odata.type' => $this->spType,
        ], $properties);

        $body = json_encode($properties);

        $this->list->request("_api/web/Lists(guid'".$this->list->getGUID()."')/items(".$this->id.")", [
            'headers' => [
                'Authorization'   => 'Bearer '.$this->list->getSPAccessToken(),
                'Accept'          => 'application/json',
                'X-RequestDigest' => $this->list->getSPContextInfo()->getFormDigest(),
                'X-HTTP-Method'   => 'MERGE',
                'IF-MATCH'        => '*',
                'Content-type'    => 'application/json',
                'Content-length'  => strlen($body),
            ],

            'body'    => $body,

        ], 'POST');

        // Rehydration is done using the $properties array,
        // since the SharePoint API doesn't return a response
        // on a successful update
        return $this->hydrate($properties, true);
    }

    /**
     * Recycle a SharePoint Item
     *
     * @throws  SPRuntimeException
     * @return  string
     */
    public function recycle()
    {
        $json = $this->list->request("_api/web/Lists(guid'".$this->list->getGUID()."')/items(".$this->id.")/recycle", [
            'headers' => [
                'Authorization'   => 'Bearer '.$this->list->getSPAccessToken(),
                'Accept'          => 'application/json',
                'X-RequestDigest' => $this->list->getSPContextInfo()->getFormDigest(),
            ],
        ], 'POST');

        // Return the the recycle bin item GUID
        return $json['value'];
    }

    /**
     * Delete a SharePoint Item
     *
     * @throws  SPRuntimeException
     * @return  bool
     */
    public function delete()
    {
        $this->list->request("_api/web/Lists(guid'".$this->list->getGUID()."')/items(".$this->id.")", [
            'headers' => [
                'Authorization'   => 'Bearer '.$this->list->getSPAccessToken(),
                'X-RequestDigest' => $this->list->getSPContextInfo()->getFormDigest(),
                'IF-MATCH'        => '*',
                'X-HTTP-Method'   => 'DELETE',
            ],
        ], 'POST');

        return true;
    }
}
